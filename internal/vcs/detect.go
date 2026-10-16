// Marker-based VCS detection: marker-name validation and single-directory probing.
package vcs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// builtinMarkers maps each built-in VCS name to the filesystem entry that marks a repository root.
// It is kept aligned with the embedded built-in templates (internal/vcs/builtin) and is consumed by auto-detect.
var builtinMarkers = map[string]string{
	"git": ".git",
	"hg":  ".hg",
	"jj":  ".jj",
}

// ValidateMarker reports whether marker names a single filesystem entry rather than a path.
// A valid marker is non-empty; contains no '/', '\', or NUL; is at most 255 UTF-8 bytes; is neither
// "." nor ".."; and has no leading or trailing ASCII whitespace. The returned error describes the violation.
func ValidateMarker(marker string) error {
	if marker == "" {
		return errors.New("marker must be a non-empty string")
	}
	if strings.ContainsAny(marker, "/\\\x00") {
		return errors.New(`marker must not contain '/', '\', or NUL`)
	}
	if len(marker) > 255 {
		return errors.New("marker UTF-8 byte length exceeds 255")
	}
	if marker == "." || marker == ".." {
		return errors.New("marker must not be '.' or '..'")
	}
	if trimASCIISpace(marker) != marker {
		return errors.New("marker must not have leading or trailing ASCII whitespace")
	}
	return nil
}

// DetectInDir reports whether dir directly contains an entry named marker. It validates marker before
// joining paths so an invalid marker can never become a path-traversal or nested-path probe. The probe is an
// lstat (no symlink follow): any entry type counts as present. A missing entry yields (false, nil); any other
// filesystem error is returned.
func DetectInDir(dir, marker string) (bool, error) {
	if err := ValidateMarker(marker); err != nil {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(dir, marker)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// trimASCIISpace returns s without leading or trailing ASCII whitespace (space, tab, NL, VT, FF, CR).
// Unicode whitespace is intentionally not trimmed: names ASCII whitespace only.
func trimASCIISpace(s string) string {
	start := 0
	for start < len(s) && isASCIISpaceByte(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isASCIISpaceByte(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isASCIISpaceByte(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}
