// Pending image-attachment model and the file-reference → data-URI encoder shared
// by the '@' picker, pasted/typed path recognition, and the clipboard source:
// it resolves a referenced path under the project root, enforces the size cap,
// sniffs the image type, and builds the persisted image_url content part.
package tui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/sessions"
)

// maxImageBytes caps a single attached image's on-disk size. Base64 inflates the
// payload ~33% in the persisted record and the provider request, so the cap is a
// deliberate conservative ceiling rather than a provider hard limit. The oversize
// test references this constant instead of duplicating the literal.
const maxImageBytes = 10 << 20 // 10 MiB

// supportedImageExts is the set of extensions the '@' picker and typed-path
// recognition treat as candidate images (the cheap first gate before the content
// sniff). Lowercased; filepath.Ext includes the leading dot.
var supportedImageExts = map[string]struct{}{
	".png":  {},
	".jpg":  {},
	".jpeg": {},
	".gif":  {},
	".webp": {},
}

// Sentinel reasons resolveImageAttachment returns, so callers can tell a
// "looked like an image by name but is not one" case (inline it as text, like any
// non-image reference) apart from a real failure that warrants a friendly notice.
var (
	// errNotAnImage means the path is not a supported image — either its extension
	// is not an image extension or its bytes did not sniff as png/jpeg/gif/webp. The
	// '@' picker falls back to inlining the reference as text in this case.
	errNotAnImage = errors.New("not a supported image file")
	// errImageTooLarge means the file exceeds maxImageBytes.
	errImageTooLarge = fmt.Errorf("image is larger than the %d MB limit", maxImageBytes>>20)
	// errImageIgnored means the path is excluded by codemeldignore.
	errImageIgnored = errors.New("path is excluded by codemeldignore")
	// errImageOutsideRoot means an explicit image-extension reference escapes the
	// project root — an absolute or traversal path whose parent or target lies outside
	// the root, or a path resolving through a symlink to outside it. Unlike a missing
	// in-root name (left as prose), it must block submission so an out-of-root reference
	// is never silently sent to the model as prompt text.
	errImageOutsideRoot = errors.New("path is outside the project root")
)

// imageAttachment is one pending image attached to the prompt: the referenced path, an
// optional display name override, the sniffed mime, the byte size, and the data: URI sent to
// the model. It is created by resolveImageAttachment (file references) or newClipboardAttachment
// (clipboard) and held on inputField as an image token until the prompt is submitted or cleared.
type imageAttachment struct {
	path string
	// name is the display label shown in the input token and the transcript placeholder when
	// set: "Image N" for a clipboard image, the basename for a file reference. inputField.addAttachment
	// records it so the placeholder reads the same name the user saw in the token, decoupling the
	// shown name from path. Empty falls back to the path's basename (displayName).
	name      string
	mime      string
	sizeBytes int64
	dataURI   string
}

// displayName is the name shown for the attachment in the input token and the transcript
// "[image: name (size)]" placeholder: the recorded name override when set (a clipboard
// image's "Image N"), otherwise the referenced file's basename.
func (a imageAttachment) displayName() string {
	if a.name != "" {
		return a.name
	}
	return filepath.Base(a.path)
}

// isImageExtension reports whether name's extension is one codemeld treats as a
// candidate image. It is the cheap gate run before any filesystem read, so an
// ordinary prose token (no image extension) never triggers a path resolution.
func isImageExtension(name string) bool {
	_, ok := supportedImageExts[strings.ToLower(filepath.Ext(name))]
	return ok
}

// outsideRootReason reports whether a filetools read-boundary rejection reason
// describes an out-of-root or symlink-escape failure rather than a benign missing
// reference. It keys on the "outside the project root" phrasing shared by the three
// containment rejections (parent outside root, target outside root, symlink-to-outside
// at internal/filetools/readresolve.go); a missing file, missing parent directory, or
// ~user form does not contain it and stays prose.
func outsideRootReason(reason string) bool {
	return strings.Contains(reason, "outside the project root")
}

// imageAttachErrorNotice formats the friendly one-line rejection shown when an
// explicit image reference cannot become a pending attachment.
func imageAttachErrorNotice(rawPath string, err error) string {
	return fmt.Sprintf("cannot attach %s: %v", filepath.Base(rawPath), err)
}

// sniffImageMime returns the canonical mime for data's magic bytes when they match
// one of the four supported image types, or "" otherwise. Explicit magic-byte
// detection (rather than http.DetectContentType) keeps the supported set closed and
// the security-sensitive sniff auditable.
func sniffImageMime(data []byte) string {
	switch {
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return "image/jpeg"
	case len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a"):
		return "image/gif"
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return "image/webp"
	default:
		return ""
	}
}

// resolveImageAttachment resolves rawPath (project-relative or absolute) to a
// pending image attachment, honoring the same root-confinement and codemeldignore
// rules the read-only navigation tools use. It rejects a path
// whose extension is not an image extension (errNotAnImage), one that escapes the
// project root or is not a regular file, one excluded by codemeldignore
// (errImageIgnored), one over maxImageBytes (errImageTooLarge), and one whose bytes
// do not sniff as a supported image (errNotAnImage). On success it base64-encodes
// the bytes into a data:<mime>;base64,… URI. The bytes are read from the resolved
// real file, never from rawPath directly, so a symlink cannot redirect the read out
// of the project.
func resolveImageAttachment(projectRoot, home, rawPath string) (imageAttachment, error) {
	if !isImageExtension(rawPath) {
		return imageAttachment{}, errNotAnImage
	}
	target, _, err := filetools.ResolveReadTarget(home, "", projectRoot, map[string]any{"path": rawPath}, filetools.ReadTargetOptions{RequirePath: true, Kind: "read"})
	if err != nil {
		// An explicit reference whose parent or target escapes the project root — or that
		// resolves through a symlink to outside it — is a concrete rejection that must block
		// rather than become prompt text. Any other resolution failure (a
		// missing parent directory, a ~user form) means the reference does not resolve to an
		// in-root target and stays prose like any unresolved name.
		var te *filetools.TargetError
		if errors.As(err, &te) && outsideRootReason(te.Reason) {
			return imageAttachment{}, errImageOutsideRoot
		}
		return imageAttachment{}, fmt.Errorf("cannot read image: %w", err)
	}
	real, ok, reason := filetools.ResolveReadFile(target, projectRoot)
	if !ok {
		// A symlink escape surfaced here is out-of-root and blocks; an existing target that
		// is not a usable image (a directory, a special or unreadable file) is also a
		// concrete rejection; only a target that genuinely does not exist stays prose.
		if outsideRootReason(reason) {
			return imageAttachment{}, errImageOutsideRoot
		}
		if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
			return imageAttachment{}, errNotAnImage
		}
		return imageAttachment{}, errors.New(reason)
	}
	if ignored, ierr := imagePathIgnored(projectRoot, home, real); ierr != nil {
		return imageAttachment{}, ierr
	} else if ignored {
		return imageAttachment{}, errImageIgnored
	}
	data, err := readImageBytes(real)
	if err != nil {
		return imageAttachment{}, err
	}
	mime := sniffImageMime(data)
	if mime == "" {
		return imageAttachment{}, errNotAnImage
	}
	return imageAttachment{
		path:      rawPath,
		mime:      mime,
		sizeBytes: int64(len(data)),
		dataURI:   "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data),
	}, nil
}

// newClipboardAttachment builds a pending image attachment from raw clipboard bytes,
// reusing the same size cap, magic-byte sniff, and base64 data-URI encoding the file
// reference path uses (resolveImageAttachment) — the single encode/size/sniff place.
// The clipboard carries no filename; the display name is the per-prompt
// "Image N" label the input field assigns through addAttachment, so this leaves
// name unset and the caller stamps it before the token/transcript show it. It rejects
// bytes over maxImageBytes (errImageTooLarge) and bytes that do not sniff as a supported
// image (errNotAnImage), so the clipboard source enforces the exact same image
// constraints as an attached file rather than trusting the helper's claimed mime.
func newClipboardAttachment(data []byte) (imageAttachment, error) {
	if len(data) > maxImageBytes {
		return imageAttachment{}, errImageTooLarge
	}
	mime := sniffImageMime(data)
	if mime == "" {
		return imageAttachment{}, errNotAnImage
	}
	return imageAttachment{
		mime:      mime,
		sizeBytes: int64(len(data)),
		dataURI:   "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data),
	}, nil
}

// readImageBytes reads real fully but rejects a file over maxImageBytes without
// loading the whole oversize payload: it reads one byte past the cap and treats any
// overflow as errImageTooLarge.
func readImageBytes(real string) ([]byte, error) {
	f, err := os.Open(real)
	if err != nil {
		return nil, fmt.Errorf("cannot open image: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxImageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read image: %w", err)
	}
	if len(data) > maxImageBytes {
		return nil, errImageTooLarge
	}
	return data, nil
}

// imagePathIgnored reports whether the resolved real file matches a codemeldignore
// pattern. The '@' picker already filters ignored paths from its candidate list, so
// this is the backstop that also covers pasted/typed paths. A matcher-load error is
// returned so the caller can refuse rather than attach an unfilterable path; a path
// that does not sit under projectRoot (defensive — ResolveReadFile already contains
// it) is treated as not ignored.
//
// The walker normally prunes a matched directory's whole subtree before it descends,
// so matching only the file's own path would miss a file under an ignored directory.
// This replicates that prune by also testing each ancestor directory's project-relative
// path against the matcher (a slash-less pattern like "secrets" matches the directory
// entry, not "secrets/key.png").
func imagePathIgnored(projectRoot, home, real string) (bool, error) {
	matcher, err := filetools.LoadCodemeldignoreMatcher(projectRoot, home)
	if err != nil {
		return false, fmt.Errorf("cannot load codemeldignore: %w", err)
	}
	if matcher == nil {
		return false, nil
	}
	rel, err := filepath.Rel(projectRoot, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, nil
	}
	p := filepath.ToSlash(rel)
	kind := filetools.EntryFile
	for {
		if matcher.ShouldSkip(p, kind) {
			return true, nil
		}
		i := strings.LastIndex(p, "/")
		if i < 0 {
			return false, nil
		}
		p = p[:i]
		kind = filetools.EntryDir
	}
}

// imagePart builds the persisted image_url content part for this attachment in the
// exact raw shape the provider send path consumes — {"type":"image_url","image_url":
// {"url":"data:…"}} — plus a codemeld-private "name" sibling carrying the display name
// (basename, or a clipboard image's "Image N") for the transcript placeholder.
// The send path's userContentParts reads
// only type and image_url.url, so "name" never reaches the provider wire; it is
// preserved verbatim in the session record (sessions.ContentPart holds the raw part
// object) so /resume replay can render the same placeholder the live echo shows. No
// schema_version change: this uses the existing list-valued content shape.
func (a imageAttachment) imagePart() sessions.ContentPart {
	return imageURLContentPart(a.dataURI, a.displayName())
}

// imageURLContentPart marshals one image_url content part: the send-path-consumed
// {"type":"image_url","image_url":{"url":url}} plus the codemeld-private "name"
// sibling for the transcript placeholder (see imagePart). Field order is type,
// name, image_url (struct declaration order). The marshal cannot fail for these
// string fields, so the error is discarded.
func imageURLContentPart(url, name string) sessions.ContentPart {
	raw, _ := json.Marshal(struct {
		Type     string `json:"type"`
		Name     string `json:"name,omitempty"`
		ImageURL struct {
			URL string `json:"url"`
		} `json:"image_url"`
	}{
		Type: "image_url",
		Name: name,
		ImageURL: struct {
			URL string `json:"url"`
		}{URL: url},
	})
	return sessions.ContentPart{Type: "image_url", Raw: raw}
}
