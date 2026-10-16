// Tests for ResolveHome, FormatHomeError, and Expand reason strings and tilde-expansion behavior.
package paths

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func unsetHOME(t *testing.T) {
	t.Helper()
	orig, had := os.LookupEnv("HOME")
	if err := os.Unsetenv("HOME"); err != nil {
		t.Fatalf("unsetenv HOME: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("HOME", orig)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
}

func setCurrentUser(t *testing.T, fn func() (*user.User, error)) {
	t.Helper()
	prev := currentUser
	currentUser = fn
	t.Cleanup(func() { currentUser = prev })
}

func TestResolveHome_HomeSetAndValid(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	home, err := ResolveHome()
	if err != nil {
		t.Fatalf("ResolveHome error: %v", err)
	}
	if home != dir {
		t.Fatalf("ResolveHome = %q, want %q", home, dir)
	}
}

// TestResolveHome_IndependentOfWorkingDirectory pins that home resolution is
// anchored at $HOME and never derived from the current working directory, even
// when that directory looks like a codemeld project root (it carries a .codemeld
// folder). Global auth state lives under the resolved home, so this guards the
// platform invariant that credentials are not located relative to the project
// root regardless of where codemeld is launched.
func TestResolveHome_IndependentOfWorkingDirectory(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	// A decoy project root: a different directory carrying a .codemeld folder.
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".codemeld"), 0o700); err != nil {
		t.Fatalf("seed project .codemeld: %v", err)
	}
	t.Chdir(projectDir)

	home, err := ResolveHome()
	if err != nil {
		t.Fatalf("ResolveHome error: %v", err)
	}
	if home != homeDir {
		t.Fatalf("ResolveHome = %q, want %q (must follow $HOME, not the working directory)", home, homeDir)
	}
}

func TestResolveHome_HomeMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-home")
	t.Setenv("HOME", missing)

	home, err := ResolveHome()
	if err == nil {
		t.Fatalf("ResolveHome on missing path = %q, want error", home)
	}
	if !errors.Is(err, errHomeMissing) {
		t.Fatalf("err = %v, want errHomeMissing", err)
	}
	if home != "" {
		t.Fatalf("home = %q on failure, want empty", home)
	}
}

func TestResolveHome_HomeUnsetUserSuccess(t *testing.T) {
	unsetHOME(t)

	fakeHome := t.TempDir()
	setCurrentUser(t, func() (*user.User, error) {
		return &user.User{HomeDir: fakeHome}, nil
	})

	home, err := ResolveHome()
	if err != nil {
		t.Fatalf("ResolveHome error: %v", err)
	}
	if home != fakeHome {
		t.Fatalf("ResolveHome = %q, want %q", home, fakeHome)
	}
}

func TestResolveHome_HomeUnsetUserEmpty(t *testing.T) {
	unsetHOME(t)
	setCurrentUser(t, func() (*user.User, error) {
		return &user.User{HomeDir: ""}, nil
	})

	home, err := ResolveHome()
	if err == nil {
		t.Fatalf("ResolveHome with empty user.HomeDir = %q, want error", home)
	}
	if !errors.Is(err, errHomeUnset) {
		t.Fatalf("err = %v, want errHomeUnset", err)
	}
}

func TestResolveHome_HomeUnsetUserFailure(t *testing.T) {
	unsetHOME(t)
	lookupErr := errors.New("synthetic user lookup failure")
	setCurrentUser(t, func() (*user.User, error) {
		return nil, lookupErr
	})

	home, err := ResolveHome()
	if err == nil {
		t.Fatalf("ResolveHome with failing lookup = %q, want error", home)
	}
	if !errors.Is(err, lookupErr) {
		t.Fatalf("err does not wrap synthetic lookup error: %v", err)
	}
}

func TestResolveHome_HomeEmptyFallsBack(t *testing.T) {
	t.Setenv("HOME", "")
	fakeHome := t.TempDir()
	setCurrentUser(t, func() (*user.User, error) {
		return &user.User{HomeDir: fakeHome}, nil
	})

	home, err := ResolveHome()
	if err != nil {
		t.Fatalf("ResolveHome error: %v", err)
	}
	if home != fakeHome {
		t.Fatalf("ResolveHome = %q, want %q", home, fakeHome)
	}
}

func TestFormatHomeError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"home unset", errHomeUnset, "$HOME unset"},
		{"home missing", errHomeMissing, "$HOME points to a path that does not exist"},
		{"user lookup", fmt.Errorf("os/user lookup failed: %w", errors.New("boom")), "os/user lookup failed: boom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FormatHomeError(c.err); got != c.want {
				t.Fatalf("FormatHomeError = %q, want %q", got, c.want)
			}
		})
	}
}

func TestExpand(t *testing.T) {
	home := "/home/u"
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"tilde only", "~", "/home/u", false},
		{"tilde slash", "~/", "/home/u", false},
		{"tilde subpath", "~/.config/codemeld", "/home/u/.config/codemeld", false},
		{"tilde nested", "~/a/b/c", "/home/u/a/b/c", false},
		{"absolute", "/etc/passwd", "/etc/passwd", false},
		{"relative", "foo/bar", "foo/bar", false},
		{"empty", "", "", false},
		{"tilde user with slash", "~root/.bashrc", "", true},
		{"tilde user no slash", "~root", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Expand(home, c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Expand(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Expand(%q) error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("Expand(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
