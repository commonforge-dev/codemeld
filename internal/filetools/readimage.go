// Built-in read-only image tool.
package filetools

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/tools"
)

const ReadImageToolName = "read_image"

const maxReadImageBytes = 10 << 20

type ReadImageTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
}

var _ tools.Tool = (*ReadImageTool)(nil)

func NewReadImageTool(home, processCWD, projectRoot string, outputCap int) *ReadImageTool {
	return &ReadImageTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *ReadImageTool) Name() string { return ReadImageToolName }

func (t *ReadImageTool) SubjectKind() string { return "tool" }

func (t *ReadImageTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Read an image file (PNG, JPEG, GIF, or WEBP) so you can see it. " +
			"Give the path of one image you have already discovered; its pixels are provided to you as " +
			"visual input and a short line reports its type and size. Use this only for images; use read " +
			"for text files.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Path of the image file to read. Relative paths resolve against the project root and read normally; an explicitly named path whose real location is outside the project is read only after you approve it at the permission prompt. An explicit hidden (dot-prefixed) path is honored.",
				},
			},
			"required":             []string{"path"},
			"additionalProperties": false,
		},
		ReadOnly:      true,
		Noncredential: true,
	}
}

func (t *ReadImageTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownReadImageArgs(args); verr != nil {
		return "", "", &TargetError{Kind: ReadImageToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:   true,
		Kind:          ReadImageToolName,
		AllowExternal: true,
	})
}

func (t *ReadImageTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

func (t *ReadImageTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.readImage(resolvedTarget, args), nil
}

func (t *ReadImageTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(ReadImageToolName), nil
	}
	return t.readImage(target, args), nil
}

// ValidateReadImageArgs is the complete non-executing argument check for a read_image call: it
// reads nothing and resolves no path, so an authorization group can reject a malformed call before
// preparing it.
func ValidateReadImageArgs(args map[string]any) error {
	if err := rejectUnknownReadImageArgs(args); err != nil {
		return err
	}
	path, err := requireStringArg(args, "path")
	if err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return &TargetError{Kind: ReadImageToolName, Reason: "path must be non-empty"}
	}
	return nil
}

func (t *ReadImageTool) readImage(resolvedTarget string, args map[string]any) tools.Result {
	if verr := ValidateReadImageArgs(args); verr != nil {
		return failResult(verr.Error())
	}
	mime, data, err := t.resolveAndReadImage(resolvedTarget)
	if err != nil {
		return failResult(err.Error())
	}
	notice := fmt.Sprintf("read %s (%s, %d bytes); the image is provided to you as visual input", t.displayPath(resolvedTarget), mime, len(data))
	res := BoundedResult([]byte(notice), false, 0, t.outputCap)
	res.ModelContextImage = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
	return res
}

func (t *ReadImageTool) resolveAndReadImage(resolvedTarget string) (mime string, data []byte, err error) {
	boundary := t.projectRoot
	if t.ExternalReadScope(resolvedTarget) {
		boundary = filepath.Dir(resolvedTarget)
	}
	real, ok, reason := ResolveReadFile(resolvedTarget, boundary)
	if !ok {
		return "", nil, fmt.Errorf("%s", reason)
	}
	ignored, ierr := imagePathIgnored(t.projectRoot, t.home, real)
	if ierr != nil {
		return "", nil, ierr
	}
	if ignored {
		return "", nil, fmt.Errorf("path is excluded by codemeldignore")
	}
	data, err = readCappedImageBytes(real)
	if err != nil {
		return "", nil, err
	}
	afterImageCapture()
	mime = sniffImageMime(data)
	if mime == "" {
		return "", nil, fmt.Errorf("not a supported image file (expected PNG, JPEG, GIF, or WEBP)")
	}
	return mime, data, nil
}

func (t *ReadImageTool) displayPath(real string) string {
	rel, err := filepath.Rel(t.projectRoot, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.Base(real)
	}
	return filepath.ToSlash(rel)
}

// afterImageCapture is a test seam invoked once the image bytes are in memory, so a test can
// replace the file at the same path and prove no later step reads it again.
var afterImageCapture = func() {}

func readCappedImageBytes(real string) ([]byte, error) {
	f, err := os.Open(real)
	if err != nil {
		return nil, fmt.Errorf("cannot open image: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxReadImageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read image: %w", err)
	}
	if len(data) > maxReadImageBytes {
		return nil, fmt.Errorf("image is larger than the %d MB limit", maxReadImageBytes>>20)
	}
	return data, nil
}

// Duplicated from internal/tui/imageattach.go: filetools cannot import internal/tui, so a tool-read and a
// user-attached image classify identically.
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

func imagePathIgnored(projectRoot, home, real string) (bool, error) {
	matcher, err := LoadCodemeldignoreMatcher(projectRoot, home)
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
	kind := EntryFile
	for {
		if matcher.ShouldSkip(p, kind) {
			return true, nil
		}
		i := strings.LastIndex(p, "/")
		if i < 0 {
			return false, nil
		}
		p = p[:i]
		kind = EntryDir
	}
}

var allowedReadImageArgs = map[string]struct{}{"path": {}}

func rejectUnknownReadImageArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedReadImageArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only path is accepted", key)
		}
	}
	return nil
}
