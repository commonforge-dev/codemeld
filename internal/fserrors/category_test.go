// Tests for error-category mapping, OP_FAIL formatting, control collapse, and stderr fallback.
package fserrors

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/testsupport"
)

func TestCategorizeErrno(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Category
	}{
		{"EACCES via PathError", &os.PathError{Op: "open", Path: "/x", Err: syscall.EACCES}, PermissionDenied},
		{"EPERM via PathError", &os.PathError{Op: "chmod", Path: "/x", Err: syscall.EPERM}, PermissionDenied},
		{"ENOSPC via PathError", &os.PathError{Op: "write", Path: "/x", Err: syscall.ENOSPC}, NoSpace},
		{"EROFS via PathError", &os.PathError{Op: "create", Path: "/x", Err: syscall.EROFS}, ReadOnlyFS},
		{"ENOENT via PathError", &os.PathError{Op: "open", Path: "/x", Err: syscall.ENOENT}, NotFound},
		{"EBUSY via PathError", &os.PathError{Op: "remove", Path: "/x", Err: syscall.EBUSY}, InUse},
		{"ETXTBSY via PathError", &os.PathError{Op: "open", Path: "/x", Err: syscall.ETXTBSY}, InUse},
		{"EIO falls through to io_error", &os.PathError{Op: "read", Path: "/x", Err: syscall.EIO}, IOError},
		{"bare EACCES", syscall.EACCES, PermissionDenied},
		{"non-errno error", errors.New("boom"), IOError},
		{"nil error", nil, IOError},
		{"doubly wrapped EACCES", &os.PathError{Op: "open", Path: "/x", Err: &os.SyscallError{Syscall: "open", Err: syscall.EACCES}}, PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CategorizeErrno(tt.err); got != tt.want {
				t.Fatalf("CategorizeErrno(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestCollapseControls(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"newline", "a\nb", "a b"},
		{"carriage return", "a\rb", "a b"},
		{"tab", "a\tb", "a b"},
		{"multi-line + tabs", "a\nb\tc\rd", "a b c d"},
		{"runs of spaces collapse", "a   b", "a b"},
		{"mixed controls collapse", "a \n\t b", "a b"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CollapseControls(tt.in); got != tt.want {
				t.Fatalf("CollapseControls(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatOpFail(t *testing.T) {
	got := FormatOpFail("write", "/var/lib/codemeld/x", PermissionDenied)
	want := "codemeld: write failed: /var/lib/codemeld/x: permission_denied"
	if got != want {
		t.Fatalf("FormatOpFail = %q, want %q", got, want)
	}

	got = FormatOpFail("op\nname", "path\twith\rctrl", NotFound)
	want = "codemeld: op name failed: path with ctrl: not_found"
	if got != want {
		t.Fatalf("FormatOpFail with controls = %q, want %q", got, want)
	}

	if strings.HasSuffix(got, "\n") {
		t.Fatalf("FormatOpFail should not include a trailing newline; got %q", got)
	}
}

func TestWriteToStderr(t *testing.T) {
	out := testsupport.CaptureStderr(t, func() {
		WriteToStderr("write", "/x", PermissionDenied, "")
	})
	want := "codemeld: write failed: /x: permission_denied\n"
	if out != want {
		t.Fatalf("stderr = %q, want %q", out, want)
	}
}

func TestWriteToStderrWithDetail(t *testing.T) {
	out := testsupport.CaptureStderr(t, func() {
		WriteToStderr("write", "/x", IOError, "disk\nfailed\tmid-flush")
	})
	want := "codemeld: write failed: /x: io_error\ndetail: disk failed mid-flush\n"
	if out != want {
		t.Fatalf("stderr = %q, want %q", out, want)
	}
}
