// Unit coverage for the clipboard-image reader: platform/session helper
// selection, result classification (no helper, no image, helper error, timeout), and
// the bytes → pending-attachment encoder — all driven through the injected lookPath/run
// seams so no real helper binary is ever spawned.
package tui

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// envFromMap returns a getenv-shaped lookup over m, so candidate selection can be
// tested for each platform/session without touching the real environment.
func envFromMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestClipboardHelperCandidates(t *testing.T) {
	cases := []struct {
		name  string
		goos  string
		env   map[string]string
		first string // expected first-choice helper, or "" for no candidates
		names []string
	}{
		{"macos", "darwin", nil, "pngpaste", []string{"pngpaste"}},
		{"wayland", "linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, "wl-paste", []string{"wl-paste", "xclip", "xsel"}},
		{"wayland-and-x11", "linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, "wl-paste", []string{"wl-paste", "xclip", "xsel"}},
		{"x11", "linux", map[string]string{"DISPLAY": ":0"}, "xclip", []string{"xclip", "xsel"}},
		{"headless", "linux", nil, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clipboardHelperCandidates(tc.goos, envFromMap(tc.env))
			var names []string
			for _, c := range got {
				names = append(names, c.name)
			}
			if strings.Join(names, ",") != strings.Join(tc.names, ",") {
				t.Fatalf("candidates = %v, want %v", names, tc.names)
			}
			if tc.first == "" {
				if len(got) != 0 {
					t.Fatalf("want no candidates, got %v", names)
				}
				return
			}
			if got[0].name != tc.first {
				t.Errorf("first helper = %q, want %q", got[0].name, tc.first)
			}
			// Wayland and X11 request png explicitly so the bytes carry a known type.
			if got[0].mime != "image/png" {
				t.Errorf("first helper mime = %q, want image/png", got[0].mime)
			}
		})
	}
}

// fixedLookPath returns a lookPath seam that reports only the named binaries as
// installed.
func fixedLookPath(installed ...string) func(string) (string, error) {
	set := map[string]bool{}
	for _, n := range installed {
		set[n] = true
	}
	return func(name string) (string, error) {
		if set[name] {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

func TestExecClipboardReader_NoHelperInstalled(t *testing.T) {
	r := &execClipboardReader{
		goos:     "linux",
		getenv:   envFromMap(map[string]string{"DISPLAY": ":0"}),
		lookPath: fixedLookPath(), // nothing installed
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("run must not be called when no helper is installed")
			return nil, nil
		},
	}
	_, _, ok, err := r.ReadImage(context.Background())
	if ok || !errors.Is(err, errNoClipboardHelper) {
		t.Fatalf("ReadImage = (ok=%v, err=%v), want ok=false and errNoClipboardHelper", ok, err)
	}
}

func TestExecClipboardReader_Success(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nDATA")
	var ranName string
	var ranArgs []string
	r := &execClipboardReader{
		goos:     "linux",
		getenv:   envFromMap(map[string]string{"WAYLAND_DISPLAY": "wayland-0"}),
		lookPath: fixedLookPath("wl-paste"),
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			ranName, ranArgs = name, args
			return png, nil
		},
	}
	mime, data, ok, err := r.ReadImage(context.Background())
	if !ok || err != nil {
		t.Fatalf("ReadImage = (ok=%v, err=%v), want ok=true and no error", ok, err)
	}
	if mime != "image/png" || string(data) != string(png) {
		t.Fatalf("ReadImage returned mime=%q data=%q, want image/png and the helper bytes", mime, data)
	}
	if ranName != "wl-paste" || strings.Join(ranArgs, " ") != "--type image/png" {
		t.Errorf("ran %q %v, want wl-paste --type image/png", ranName, ranArgs)
	}
}

func TestExecClipboardReader_NoImage(t *testing.T) {
	// A helper that exits non-zero (no image of the requested type on the clipboard)
	// and one that prints nothing both classify as "no image", not an error.
	for _, tc := range []struct {
		name string
		run  func(context.Context, string, ...string) ([]byte, error)
	}{
		{"non-zero exit", func(context.Context, string, ...string) ([]byte, error) {
			return nil, &exec.ExitError{}
		}},
		{"empty output", func(context.Context, string, ...string) ([]byte, error) {
			return nil, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &execClipboardReader{
				goos:     "darwin",
				getenv:   envFromMap(nil),
				lookPath: fixedLookPath("pngpaste"),
				run:      tc.run,
			}
			_, _, ok, err := r.ReadImage(context.Background())
			if ok || err != nil {
				t.Fatalf("ReadImage = (ok=%v, err=%v), want ok=false and nil error", ok, err)
			}
		})
	}
}

func TestExecClipboardReader_HelperError(t *testing.T) {
	sentinel := errors.New("boom")
	r := &execClipboardReader{
		goos:     "darwin",
		getenv:   envFromMap(nil),
		lookPath: fixedLookPath("pngpaste"),
		run: func(context.Context, string, ...string) ([]byte, error) {
			return nil, sentinel
		},
	}
	_, _, ok, err := r.ReadImage(context.Background())
	if ok || !errors.Is(err, sentinel) {
		t.Fatalf("ReadImage = (ok=%v, err=%v), want ok=false and the run error", ok, err)
	}
}

func TestExecClipboardReader_Timeout(t *testing.T) {
	// A context already past its deadline: the reader keys the timeout notice off
	// ctx.Err()==DeadlineExceeded when the helper run fails, mirroring a stuck helper
	// killed by exec.CommandContext.
	deadlined, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	r := &execClipboardReader{
		goos:     "darwin",
		getenv:   envFromMap(nil),
		lookPath: fixedLookPath("pngpaste"),
		run: func(context.Context, string, ...string) ([]byte, error) {
			return nil, context.DeadlineExceeded
		},
	}
	_, _, ok, err := r.ReadImage(deadlined)
	if ok || !errors.Is(err, errClipboardTimeout) {
		t.Fatalf("ReadImage = (ok=%v, err=%v), want ok=false and errClipboardTimeout", ok, err)
	}
}

func TestNewClipboardAttachment(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nDATA")
	att, err := newClipboardAttachment(png)
	if err != nil {
		t.Fatalf("newClipboardAttachment(png) error: %v", err)
	}
	if att.mime != "image/png" {
		t.Errorf("mime = %q, want image/png", att.mime)
	}
	// The clipboard carries no filename: newClipboardAttachment synthesizes none, leaving the
	// "Image N" display name to the input field.
	if att.path != "" {
		t.Errorf("path = %q, want empty (clipboard images get an Image N name from the input field)", att.path)
	}
	if !strings.HasPrefix(att.dataURI, "data:image/png;base64,") {
		t.Errorf("dataURI = %q, want a data:image/png;base64 URI", att.dataURI)
	}
	if int(att.sizeBytes) != len(png) {
		t.Errorf("sizeBytes = %d, want %d", att.sizeBytes, len(png))
	}
	// The persisted content part is the image_url shape the provider send path consumes.
	if part := att.imagePart(); part.Type != "image_url" || !strings.Contains(string(part.Raw), "data:image/png;base64,") {
		t.Errorf("imagePart = %+v, want an image_url part carrying the data URI", part)
	}
}

// TestClipboardAttachment_NameIsImageN proves a clipboard attachment labeled "Image N" by the
// input field renders that name in the transcript placeholder — not "clipboard.png" — so the
// live echo and /resume replay both read "[image: Image N (size)]".
func TestClipboardAttachment_NameIsImageN(t *testing.T) {
	att, err := newClipboardAttachment([]byte("\x89PNG\r\n\x1a\nDATA"))
	if err != nil {
		t.Fatalf("newClipboardAttachment error: %v", err)
	}
	att.name = "Image 1" // the label inputField.addAttachment stamps for a clipboard image
	if got := att.displayName(); got != "Image 1" {
		t.Errorf("displayName = %q, want Image 1", got)
	}
	if got := imagePlaceholder(att.imagePart()); !strings.HasPrefix(got, "[image: Image 1 (") {
		t.Errorf("placeholder = %q, want it to name the image Image 1", got)
	}
}

func TestNewClipboardAttachment_Rejects(t *testing.T) {
	if _, err := newClipboardAttachment([]byte("not an image")); !errors.Is(err, errNotAnImage) {
		t.Errorf("non-image bytes error = %v, want errNotAnImage", err)
	}
	oversize := make([]byte, maxImageBytes+1)
	copy(oversize, "\x89PNG\r\n\x1a\n")
	if _, err := newClipboardAttachment(oversize); !errors.Is(err, errImageTooLarge) {
		t.Errorf("oversize error = %v, want errImageTooLarge", err)
	}
}
