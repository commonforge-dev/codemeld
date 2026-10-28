package runner

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestFixedEnvironment_Table(t *testing.T) {
	got, err := FixedEnvironment("/h", "/p", "/t", FixedPATH, nil)
	if err != nil {
		t.Fatalf("FixedEnvironment: %v", err)
	}
	want := []string{
		"PATH=" + FixedPATH, "HOME=/h", "PWD=/p", "TMPDIR=/t", "GOCACHE=/t/go-build",
		"SHELL=/bin/sh", "TERM=dumb", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FixedEnvironment = %v, want %v", got, want)
	}

	got, err = FixedEnvironment("/h", "/p", "/t", "/a:/b", nil)
	if err != nil {
		t.Fatalf("FixedEnvironment: %v", err)
	}
	if got[0] != "PATH=/a:/b" {
		t.Fatalf("PATH entry = %q, want PATH=/a:/b", got[0])
	}
}

func TestFixedEnvironment_NoTmpDir(t *testing.T) {
	got, err := FixedEnvironment("/h", "/p", "", FixedPATH, nil)
	if err != nil {
		t.Fatalf("FixedEnvironment: %v", err)
	}
	want := []string{
		"PATH=" + FixedPATH, "HOME=/h", "PWD=/p",
		"SHELL=/bin/sh", "TERM=dumb", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FixedEnvironment = %v, want %v", got, want)
	}
	for _, a := range []string{"TMPDIR=/x", "GOCACHE=/x"} {
		if _, err := FixedEnvironment("/h", "/p", "", FixedPATH, []string{a}); !isAssignmentError(err) {
			t.Errorf("assignment %q: err = %v, want *EnvAssignmentError", a, err)
		}
	}
}

func TestFixedEnvironment_IgnoresProcessEnvironment(t *testing.T) {
	for _, name := range []string{
		"RIPGREP_CONFIG_PATH", "SSH_AUTH_SOCK", "XDG_RUNTIME_DIR", "LD_PRELOAD",
		"GIT_CONFIG_GLOBAL", "HGRCPATH", "HTTPS_PROXY",
	} {
		t.Setenv(name, "leak")
	}
	t.Setenv("PATH", t.TempDir())

	got, err := FixedEnvironment("/h", "/p", "/t", FixedPATH, nil)
	if err != nil {
		t.Fatalf("FixedEnvironment: %v", err)
	}
	for _, e := range got {
		if strings.Contains(e, "leak") {
			t.Fatalf("FixedEnvironment = %v, contains inherited entry %q", got, e)
		}
	}
	if got[0] != "PATH="+FixedPATH {
		t.Fatalf("PATH entry = %q, want PATH=%s", got[0], FixedPATH)
	}
}

func TestFixedEnvironment_Assignments(t *testing.T) {
	got, err := FixedEnvironment("/h", "/p", "/t", FixedPATH, []string{"FOO=bar", "V=$HOME/x"})
	if err != nil {
		t.Fatalf("FixedEnvironment: %v", err)
	}
	if want := []string{"FOO=bar", "V=$HOME/x"}; !reflect.DeepEqual(got[9:], want) {
		t.Fatalf("assignments = %v, want %v after the table", got[9:], want)
	}

	got, err = FixedEnvironment("/h", "/p", "/t", FixedPATH, []string{"FOO=a", "BAR=1", "FOO=b"})
	if err != nil {
		t.Fatalf("FixedEnvironment: %v", err)
	}
	if want := []string{"FOO=b", "BAR=1"}; !reflect.DeepEqual(got[9:], want) {
		t.Fatalf("assignments = %v, want %v", got[9:], want)
	}
}

func TestFixedEnvironment_RejectsAssignments(t *testing.T) {
	for _, a := range []string{
		"PATH=/x", "HOME=/x", "TMPDIR=/x", "LC_ALL=C", "GOCACHE=/x", "LD_PRELOAD=x",
		"DYLD_INSERT_LIBRARIES=x", "PYTHONSTARTUP=x", "PERL5LIB=x", "NODE_OPTIONS=x", "BASH_ENV=x",
		"ENV=x", "IFS=x", "SHELLOPTS=x", "GIT_CONFIG_GLOBAL=x", "HGRCPATH=x", "RIPGREP_CONFIG_PATH=x",
		"SSH_AUTH_SOCK=x", "DBUS_SESSION_BUS_ADDRESS=x", "XDG_RUNTIME_DIR=x", "DOCKER_HOST=x",
		"HTTPS_PROXY=x", "https_proxy=x", "Http_Proxy=x", "NO_PROXY=x", "=x", "FOO",
	} {
		env, err := FixedEnvironment("/h", "/p", "/t", FixedPATH, []string{"OK=1", a})
		var ae *EnvAssignmentError
		if !errors.As(err, &ae) {
			t.Errorf("assignment %q: err = %v, want *EnvAssignmentError", a, err)
			continue
		}
		wantName, _, _ := strings.Cut(a, "=")
		if ae.Name != wantName || env != nil {
			t.Errorf("assignment %q: Name = %q, env = %v; want Name %q and no environment", a, ae.Name, env, wantName)
		}
	}
}

func TestFixedEnvironment_AcceptsAssignments(t *testing.T) {
	for _, a := range []string{
		"GOFLAGS=-mod=mod", "PATHX=1", "MY_PATH=1", "GOPATH=/x", "LANGUAGE=en", "MYAPP_TOKEN=x", "DATABASE_URL=postgres://u:p@h/db",
	} {
		got, err := FixedEnvironment("/h", "/p", "/t", FixedPATH, []string{a})
		if err != nil {
			t.Errorf("assignment %q: %v", a, err)
			continue
		}
		if got[len(got)-1] != a {
			t.Errorf("assignment %q: last entry = %q", a, got[len(got)-1])
		}
	}
}

func TestInheritedEnvironment_WithholdsNamesAndCredentialURLs(t *testing.T) {
	for _, entry := range []string{
		"LD_PRELOAD=x", "GIT_DIR=x", "HGRCPATH=x", "SSH_AUTH_SOCK=x", "HTTPS_PROXY=x", "https_proxy=x",
		"XDG_CONFIG_HOME=x", "BASH_ENV=x", "DOCKER_HOST=x", "GITHUB_TOKEN=x", "OPENROUTER_API_KEY=x",
		"AWS_SECRET_ACCESS_KEY=x", "my_secret=x", "DB_PASSWORD=x", "SERVICE_PW=x", "SESSION_COOKIE=x",
		"PASSWD_FILE=x", "MY_CREDENTIALS=x", "STRIPE_APIKEY=x", "S3_ACCESS_KEY_ID=x", "SSL_PRIVATE_KEY_PATH=x",
		"SIGNING_KEY=x", "SMTP_PASS=x", "PROXY_AUTH=x", "AUTH_HEADER=x", "AZURE_TENANT=x", "GOOGLE_PROJECT=x",
		"GH_HOST=x", "GITLAB_HOST=x", "NPM_TOKEN_FILE=x", "CODEMELD_RUN_ID=x", "PATH=/x", "HOME=/x", "TMPDIR=/x",
		"DATABASE_URL=postgres://u:p@h/db", "PGURL=postgresql://u:p@/db", "MIRROR=see git+ssh://me:pw@host:22/x for it",
	} {
		name, _, _ := strings.Cut(entry, "=")
		inherited, withheld := InheritedEnvironment([]string{"KEEP=1", entry})
		if !slices.Equal(inherited, []string{"KEEP=1"}) || !slices.Equal(withheld, []string{name}) {
			t.Errorf("%q: inherited = %q, withheld = %q; want only KEEP=1 inherited and %q withheld", entry, inherited, withheld, name)
		}
	}
}

func TestInheritedEnvironment_KeepsOrdinaryEntries(t *testing.T) {
	environ := []string{
		"MISE_DATA_DIR=/data/coding/mise", "GOPATH=/go", "REPO_URL=https://example.com/x", "NOTE=user:password@",
		"PORTED=http://host:8080/a@b", "EMPTY=", "KEYBOARD=us", "OAUTHOR=x", "AUTHOR=x",
	}
	inherited, withheld := InheritedEnvironment(environ)
	if !slices.Equal(inherited, environ) || withheld != nil {
		t.Fatalf("inherited = %q, withheld = %q; want every entry inherited and none withheld", inherited, withheld)
	}
}

func TestInheritedEnvironment_SortsWithheldAndDedupesLastWins(t *testing.T) {
	inherited, withheld := InheritedEnvironment([]string{
		"ZED_TOKEN=x", "A=1", "noequals", "=empty", "LD_PRELOAD=x", "A=2", "B=1", "B=postgres://u:p@h/db", "C=postgres://u:p@h/db", "C=3",
	})
	if !slices.Equal(inherited, []string{"A=2", "C=3"}) || !slices.Equal(withheld, []string{"B", "LD_PRELOAD", "ZED_TOKEN"}) {
		t.Fatalf("inherited = %q, withheld = %q", inherited, withheld)
	}
}

func TestResolveOnPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "onlyhere")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	var nf *ExecutableNotFoundError
	if _, err := ResolveOnPath("onlyhere", FixedPATH); !errors.As(err, &nf) {
		t.Fatalf("ResolveOnPath(onlyhere, FixedPATH) err = %v, want *ExecutableNotFoundError", err)
	}
	if got, err := ResolveOnPath("onlyhere", dir); err != nil || got != exe {
		t.Fatalf("ResolveOnPath(onlyhere, %s) = %q, %v; want %q", dir, got, err, exe)
	}
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "onlyhere"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := ResolveOnPath("onlyhere", "bin:"); !errors.As(err, &nf) {
		t.Fatalf("ResolveOnPath(onlyhere, bin:) err = %v, want *ExecutableNotFoundError", err)
	}
	fifoDir := filepath.Join(dir, "fifo")
	if err := os.Mkdir(fifoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(fifoDir, "onlyhere")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveOnPath("onlyhere", fifoDir+":"+dir); err != nil || got != exe {
		t.Fatalf("ResolveOnPath(onlyhere, fifo:dir) = %q, %v; want %q", got, err, exe)
	}
	if _, err := ResolveOnPath("onlyhere", fifoDir); !errors.As(err, &nf) {
		t.Fatalf("ResolveOnPath(onlyhere, fifo) err = %v, want *ExecutableNotFoundError", err)
	}
	if _, err := ResolveOnPath("", FixedPATH); !errors.As(err, &nf) {
		t.Fatalf("ResolveOnPath(\"\") err = %v, want *ExecutableNotFoundError", err)
	}

	got, err := ResolveOnPath("sh", FixedPATH)
	if err != nil {
		t.Fatalf("ResolveOnPath(sh): %v", err)
	}
	if !slices.Contains(filepath.SplitList(FixedPATH), filepath.Dir(got)) {
		t.Fatalf("ResolveOnPath(sh) = %q, not inside a FixedPATH directory", got)
	}

	for _, name := range []string{"./x", "/abs/x"} {
		if got, err := ResolveOnPath(name, FixedPATH); err != nil || got != name {
			t.Fatalf("ResolveOnPath(%q) = %q, %v; want it unchanged", name, got, err)
		}
	}
}

func isAssignmentError(err error) bool {
	var ae *EnvAssignmentError
	return errors.As(err, &ae)
}
