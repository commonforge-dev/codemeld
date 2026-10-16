package filetools

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func imageBytes(format string) []byte {
	switch format {
	case "png":
		return []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDRpixels")
	case "jpeg":
		return []byte("\xFF\xD8\xFF\xE0\x00\x10JFIFbody")
	case "gif":
		return []byte("GIF89a\x01\x00\x01\x00frames")
	case "webp":
		return []byte("RIFF\x24\x00\x00\x00WEBPVP8 data")
	default:
		return []byte("not an image at all")
	}
}

func newImageTool(t *testing.T) (*ReadImageTool, string) {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	return NewReadImageTool(home, project, project, 65536), project
}

func invokeImage(t *testing.T, tool *ReadImageTool, path string) (stdout, stderr string, exit int, image string) {
	t.Helper()
	res, err := tool.Invoke(context.Background(), map[string]any{"path": path})
	if err != nil {
		t.Fatalf("Invoke(%q) error = %v, want nil (all failures are in-band)", path, err)
	}
	return string(res.Stdout), string(res.Stderr), res.ExitCode, res.ModelContextImage
}

func TestReadImageTool_SupportedFormats(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		format string
		mime   string
	}{
		{"png", "logo.png", "png", "image/png"},
		{"jpeg", "photo.jpg", "jpeg", "image/jpeg"},
		{"gif", "anim.gif", "gif", "image/gif"},
		{"webp", "pic.webp", "webp", "image/webp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, project := newImageTool(t)
			data := imageBytes(tc.format)
			if err := os.WriteFile(filepath.Join(project, tc.file), data, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			stdout, _, exit, uri := invokeImage(t, tool, tc.file)
			if exit != 0 {
				t.Fatalf("read_image(%s) exit = %d, want 0", tc.file, exit)
			}
			if !strings.Contains(stdout, tc.mime) {
				t.Fatalf("metadata = %q, want it to name %q", stdout, tc.mime)
			}
			if strings.Contains(stdout, "data:") || strings.Contains(stdout, "base64") {
				t.Fatalf("metadata = %q, leaked a data URI into tool stdout", stdout)
			}

			wantPrefix := "data:" + tc.mime + ";base64,"
			if !strings.HasPrefix(uri, wantPrefix) {
				t.Fatalf("data URI = %q, want prefix %q", uri, wantPrefix)
			}
			if strings.Contains(uri, "\n") || len(uri) <= len(wantPrefix) {
				t.Fatalf("data URI = %q, want a non-empty single-line base64 payload", uri)
			}
			decoded, derr := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, wantPrefix))
			if derr != nil {
				t.Fatalf("data URI payload = %v, want valid base64", derr)
			}
			// The notice and the visual input must describe the same capture, so a byte count
			// that disagrees with the encoded payload means the result was built from a
			// different read than the image.
			if !bytes.Equal(decoded, data) || !strings.Contains(stdout, fmt.Sprintf("%d bytes", len(decoded))) {
				t.Fatalf("metadata %q and data URI (%d bytes) describe different reads of %s", stdout, len(decoded), tc.file)
			}
		})
	}
}

// A second read of the same path would pick up the replacement, so the notice and the data URI
// would describe different bytes. One capture makes both describe the original.
func TestReadImageTool_SamePathReplacementCannotSplitTheCapture(t *testing.T) {
	tool, project := newImageTool(t)
	original := imageBytes("png")
	replacement := append(imageBytes("gif"), []byte("much longer replacement body")...)
	target := filepath.Join(project, "logo.png")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	orig := afterImageCapture
	t.Cleanup(func() { afterImageCapture = orig })
	swapped := 0
	afterImageCapture = func() {
		swapped++
		if err := os.WriteFile(target, replacement, 0o644); err != nil {
			t.Fatalf("replace image: %v", err)
		}
	}

	stdout, _, exit, image := invokeImage(t, tool, "logo.png")
	if exit != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s", exit, stdout)
	}
	if swapped != 1 {
		t.Fatalf("captures = %d, want exactly 1 — the tool read the target more than once", swapped)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(image, "data:image/png;base64,"))
	if err != nil {
		t.Fatalf("data URI is not the png the tool captured: %v (%q)", err, image)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("data URI carries %d bytes, want the %d captured before the replacement", len(decoded), len(original))
	}
	if !strings.Contains(stdout, fmt.Sprintf("image/png, %d bytes", len(original))) {
		t.Fatalf("metadata %q does not describe the captured bytes (image/png, %d bytes)", stdout, len(original))
	}
	if current, err := os.ReadFile(target); err != nil || bytes.Equal(current, original) {
		t.Fatalf("the fixture did not replace the image, so a second read could not be detected (err=%v)", err)
	}
}

func TestReadImageTool_ResolveTargetResolvesExplicitOutsideImage(t *testing.T) {
	tool, _ := newImageTool(t)
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	path := filepath.Join(outside, "ext.png")
	if err := os.WriteFile(path, imageBytes("png"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	args := map[string]any{"path": path}

	target, scope, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget(%q) error = %v, want the explicit outside image resolved", path, err)
	}
	if target != path || !tool.ExternalReadScope(scope) {
		t.Fatalf("ResolveTarget = (%q, %q), want %q with an external scope", target, scope, path)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil || res.ExitCode != 0 || !strings.HasPrefix(res.ModelContextImage, "data:image/png;base64,") {
		t.Fatalf("InvokeWithResolvedTarget = (%+v, %v), want the outside png read", res, err)
	}

	_, stderr, exit, uri := invokeImage(t, tool, path)
	if exit == 0 || uri != "" || !strings.Contains(stderr, "requires permission approval through dispatch") {
		t.Fatalf("standalone Invoke = exit %d, stderr %q, uri %q; want the dispatch-only refusal", exit, stderr, uri)
	}
}

func TestReadImageTool_Refusals(t *testing.T) {
	t.Run("non-image content", func(t *testing.T) {
		tool, project := newImageTool(t)
		if err := os.WriteFile(filepath.Join(project, "notes.png"), []byte("just some text, not an image"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		assertImageRefused(t, tool, "notes.png", "just some text")
	})

	t.Run("codemeldignore excluded", func(t *testing.T) {
		tool, project := newImageTool(t)
		if err := os.MkdirAll(filepath.Join(project, ".codemeld"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(ProjectCodemeldignorePath(project), []byte("secret.png\n"), 0o644); err != nil {
			t.Fatalf("write codemeldignore: %v", err)
		}
		if err := os.WriteFile(filepath.Join(project, "secret.png"), imageBytes("png"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, stderr, exit, uri := invokeImage(t, tool, "secret.png")
		if exit == 0 {
			t.Fatalf("read_image on a codemeldignore'd image succeeded, want a refusal")
		}
		if !strings.Contains(stderr, "codemeldignore") {
			t.Fatalf("refusal = %q, want it to name codemeldignore", stderr)
		}
		if uri != "" {
			t.Fatalf("refused ignored image carried a data URI: %q", uri)
		}
	})

	t.Run("relative traversal escape", func(t *testing.T) {
		tool, _ := newImageTool(t)
		assertImageRefused(t, tool, filepath.Join("..", "outside.png"), "")
	})

	t.Run("absolute out-of-root escape", func(t *testing.T) {
		tool, _ := newImageTool(t)
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outside, "ext.png"), imageBytes("png"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		assertImageRefused(t, tool, filepath.Join(outside, "ext.png"), "")
	})

	t.Run("symlink escapes the root", func(t *testing.T) {
		tool, project := newImageTool(t)
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		target := filepath.Join(outside, "real.png")
		if err := os.WriteFile(target, imageBytes("png"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(project, "link.png")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		_, _, exit, uri := invokeImage(t, tool, "link.png")
		if exit == 0 {
			t.Fatalf("read_image followed a symlink out of the project, want a refusal")
		}
		if uri != "" {
			t.Fatalf("refused symlink escape carried a data URI: %q", uri)
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		tool, project := newImageTool(t)
		big := append(imageBytes("png"), bytes.Repeat([]byte("A"), maxReadImageBytes)...)
		if err := os.WriteFile(filepath.Join(project, "huge.png"), big, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, stderr, exit, uri := invokeImage(t, tool, "huge.png")
		if exit == 0 {
			t.Fatalf("read_image on an oversized image succeeded, want a refusal")
		}
		if !strings.Contains(stderr, "larger than") {
			t.Fatalf("refusal = %q, want the size-limit message", stderr)
		}
		if uri != "" {
			t.Fatalf("refused oversized image carried a data URI: %q", uri)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		tool, _ := newImageTool(t)
		assertImageRefused(t, tool, "nope.png", "")
	})

	t.Run("directory target", func(t *testing.T) {
		tool, project := newImageTool(t)
		if err := os.MkdirAll(filepath.Join(project, "images"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		assertImageRefused(t, tool, "images", "")
	})
}

func assertImageRefused(t *testing.T, tool *ReadImageTool, path, leakMarker string) {
	t.Helper()
	stdout, stderr, exit, uri := invokeImage(t, tool, path)
	if exit == 0 {
		t.Fatalf("read_image(%q) exit = 0, want a non-zero refusal", path)
	}
	if stdout != "" {
		t.Fatalf("read_image(%q) stdout = %q, want empty on refusal", path, stdout)
	}
	if strings.Contains(stderr, "data:") || strings.Contains(stderr, "base64") {
		t.Fatalf("refusal = %q, leaked a data URI", stderr)
	}
	if leakMarker != "" && strings.Contains(stderr, leakMarker) {
		t.Fatalf("refusal = %q, leaked file content %q", stderr, leakMarker)
	}
	if uri != "" {
		t.Fatalf("read_image(%q) carried a data URI for a refused read: %q", path, uri)
	}
}

func TestValidateReadImageArgs(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		ok   bool
	}{
		{"valid path", map[string]any{"path": "logo.png"}, true},
		{"missing path", map[string]any{}, false},
		{"blank path", map[string]any{"path": "   "}, false},
		{"non-string path", map[string]any{"path": 7}, false},
		{"unknown argument", map[string]any{"path": "logo.png", "limit": 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReadImageArgs(tc.args)
			if tc.ok && err != nil {
				t.Fatalf("ValidateReadImageArgs(%v) = %v, want nil", tc.args, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ValidateReadImageArgs(%v) = nil, want a rejection", tc.args)
			}
		})
	}
}

func TestReadImageTool_UnknownArgRejected(t *testing.T) {
	tool, project := newImageTool(t)
	if err := os.WriteFile(filepath.Join(project, "logo.png"), imageBytes("png"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res, err := tool.Invoke(context.Background(), map[string]any{"path": "logo.png", "offset": 2})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("read_image accepted an unknown argument, want a refusal")
	}
	if !strings.Contains(string(res.Stderr), "unexpected argument") {
		t.Fatalf("refusal = %q, want it to name the unexpected argument", res.Stderr)
	}
}
