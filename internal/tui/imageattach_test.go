// Tests for the image-attachment producer: extension+content-sniff acceptance
// of png/jpeg/gif/webp, root-confinement and codemeldignore rejection, the size cap,
// the data-URI encoding, and the persisted image_url part + placeholder rendering.
package tui

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/filetools"
)

// Minimal magic-byte prefixes the explicit sniffer recognizes for each supported type.
const (
	pngMagic  = "\x89PNG\r\n\x1a\n"
	jpegMagic = "\xFF\xD8\xFF"
	gifMagic  = "GIF89a"
	webpMagic = "RIFF\x00\x00\x00\x00WEBP"
)

func TestResolveImageAttachment_AcceptsSupportedTypes(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		content  string
		wantMime string
	}{
		{"png", "a.png", pngMagic + "rest", "image/png"},
		{"jpeg via .jpg", "a.jpg", jpegMagic + "rest", "image/jpeg"},
		{"jpeg via .jpeg", "a.jpeg", jpegMagic + "rest", "image/jpeg"},
		{"gif", "a.gif", gifMagic + "rest", "image/gif"},
		{"webp", "a.webp", webpMagic + "rest", "image/webp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := t.TempDir()
			writeFile(t, filepath.Join(root, tc.file), tc.content)

			att, err := resolveImageAttachment(root, home, tc.file)
			if err != nil {
				t.Fatalf("resolveImageAttachment(%q) error = %v", tc.file, err)
			}
			if att.mime != tc.wantMime {
				t.Errorf("mime = %q, want %q", att.mime, tc.wantMime)
			}
			if att.sizeBytes != int64(len(tc.content)) {
				t.Errorf("sizeBytes = %d, want %d", att.sizeBytes, len(tc.content))
			}
			wantPrefix := "data:" + tc.wantMime + ";base64,"
			if !strings.HasPrefix(att.dataURI, wantPrefix) {
				t.Fatalf("dataURI = %q, want prefix %q", att.dataURI, wantPrefix)
			}
			// The data URI round-trips back to the exact file bytes.
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(att.dataURI, wantPrefix))
			if err != nil {
				t.Fatalf("data URI payload is not valid base64: %v", err)
			}
			if string(decoded) != tc.content {
				t.Errorf("decoded payload = %q, want the original file bytes %q", decoded, tc.content)
			}
		})
	}
}

func TestResolveImageAttachment_ExtensionAndSniffMustAgree(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	// Image extension but the bytes are plain text: not a supported image.
	writeFile(t, filepath.Join(root, "fake.png"), "this is not a png")
	// Real PNG bytes but a non-image extension: the extension gate rejects it first.
	writeFile(t, filepath.Join(root, "real.txt"), pngMagic+"data")

	if _, err := resolveImageAttachment(root, home, "fake.png"); !errors.Is(err, errNotAnImage) {
		t.Errorf("png extension with non-image bytes: err = %v, want errNotAnImage", err)
	}
	if _, err := resolveImageAttachment(root, home, "real.txt"); !errors.Is(err, errNotAnImage) {
		t.Errorf("png bytes with .txt extension: err = %v, want errNotAnImage", err)
	}
}

func TestResolveImageAttachment_RejectsOversize(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	// One byte past the cap, still a valid PNG by magic bytes, so only the size check fires.
	oversize := pngMagic + strings.Repeat("\x00", maxImageBytes+1-len(pngMagic))
	writeFile(t, filepath.Join(root, "big.png"), oversize)

	if _, err := resolveImageAttachment(root, home, "big.png"); !errors.Is(err, errImageTooLarge) {
		t.Fatalf("oversize image: err = %v, want errImageTooLarge", err)
	}
}

func TestResolveImageAttachment_RejectsOutOfRoot(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.png"), pngMagic+"data")

	// An absolute path outside the project root must be refused fail-closed.
	if _, err := resolveImageAttachment(root, home, filepath.Join(outside, "secret.png")); err == nil {
		t.Fatal("out-of-root image path resolved without error; the root-confinement boundary did not fire")
	}
}

// TestResolveImageAttachment_OutOfRootIsConcreteRejection proves the root-confinement
// and symlink-escape failures are classified as concrete (blocking) rejections — not
// missing references — so an explicit out-of-root image token never falls through to
// prompt text, while a genuinely missing in-root name still stays prose.
func TestResolveImageAttachment_OutOfRootIsConcreteRejection(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.png"), pngMagic+"data")

	// Absolute path outside the root: a concrete rejection that must block.
	_, absErr := resolveImageAttachment(root, home, filepath.Join(outside, "secret.png"))
	if !errors.Is(absErr, errImageOutsideRoot) {
		t.Errorf("absolute out-of-root: err = %v, want errImageOutsideRoot", absErr)
	}
	if !isConcreteImageRejection(absErr) {
		t.Errorf("absolute out-of-root: isConcreteImageRejection = false, want true (must block, not become prose)")
	}

	// In-root symlink whose target escapes the root: also a concrete rejection. The bytes
	// are never read through the link out of the project.
	if err := os.Symlink(filepath.Join(outside, "secret.png"), filepath.Join(root, "link.png")); err != nil {
		t.Fatalf("symlink setup: %v", err)
	}
	_, linkErr := resolveImageAttachment(root, home, "link.png")
	if !errors.Is(linkErr, errImageOutsideRoot) {
		t.Errorf("in-root symlink to outside: err = %v, want errImageOutsideRoot", linkErr)
	}
	if !isConcreteImageRejection(linkErr) {
		t.Errorf("in-root symlink to outside: isConcreteImageRejection = false, want true")
	}

	// A genuinely missing in-root name is not a concrete rejection: it stays prose.
	_, missErr := resolveImageAttachment(root, home, "missing.png")
	if missErr == nil {
		t.Fatal("missing.png resolved without error, want a (non-blocking) error")
	}
	if isConcreteImageRejection(missErr) {
		t.Errorf("missing in-root name: isConcreteImageRejection = true, want false (must stay prose)")
	}
}

func TestResolveImageAttachment_RejectsCodemeldignored(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(root, "secrets", "key.png"), pngMagic+"data")
	writeFile(t, filetools.ProjectCodemeldignorePath(root), "secrets\n")

	if _, err := resolveImageAttachment(root, home, "secrets/key.png"); !errors.Is(err, errImageIgnored) {
		t.Fatalf("codemeldignored image: err = %v, want errImageIgnored", err)
	}
}

func TestImagePlaceholder_NameAndSize(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	// 2048 bytes total → 2 KB in the placeholder (1024-based).
	content := pngMagic + strings.Repeat("\x00", 2048-len(pngMagic))
	writeFile(t, filepath.Join(root, "docs", "diagram.png"), content)

	att, err := resolveImageAttachment(root, home, "docs/diagram.png")
	if err != nil {
		t.Fatalf("resolveImageAttachment error = %v", err)
	}
	// The placeholder uses the basename (not the full project-relative path) and a size
	// derived from the data URI alone, the same path /resume replay takes.
	if got, want := imagePlaceholder(att.imagePart()), "[image: diagram.png (2 KB)]"; got != want {
		t.Errorf("imagePlaceholder = %q, want %q", got, want)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{823, "823 B"},
		{1024, "1 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1 MB"},
		{1024*1024 + 512*1024, "1.5 MB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
