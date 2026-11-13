package enforce

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func denyStat(t *testing.T, path string) *unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return &st
}

func TestDenyListPathsAreTheStandardSockets(t *testing.T) {
	paths, globs := denyListPaths("/", 1000, "/tmp/ssh-x/agent.1", "unix:path=/run/user/1000/bus,guid=ab;unix:abstract=x;tcp:host=h;unix:tmpdir=/tmp,path=/tmp/a%20b")
	want := []string{
		"/run/user/1000/systemd/private",
		"/run/user/1000/bus",
		"/run/dbus/system_bus_socket",
		"/run/docker.sock",
		"/run/user/1000/docker.sock",
		"/run/user/1000/bus",
		"/tmp/a b",
		"/tmp/ssh-x/agent.1",
	}
	if !slices.Equal(paths, want) {
		t.Errorf("paths\n got %q\nwant %q", paths, want)
	}
	if want := []string{"/run/user/1000/gnupg/S.*"}; !slices.Equal(globs, want) {
		t.Errorf("globs %q, want %q", globs, want)
	}
	if paths, _ := denyListPaths("/", 7, "", ""); len(paths) != 5 {
		t.Errorf("with no agent or session bus: %q, want the five fixed paths", paths)
	}
}

func TestDenyListDeniesEachListedSocket(t *testing.T) {
	root := brkRealDir(t)
	ssh, bus := filepath.Join(root, "agent.sock"), filepath.Join(root, "session.bus")
	listed := []string{
		filepath.Join(root, "run/user/4242/systemd/private"),
		filepath.Join(root, "run/user/4242/bus"),
		filepath.Join(root, "run/dbus/system_bus_socket"),
		filepath.Join(root, "run/docker.sock"),
		filepath.Join(root, "run/user/4242/docker.sock"),
		filepath.Join(root, "run/user/4242/gnupg/S.gpg-agent"),
		filepath.Join(root, "run/user/4242/gnupg/S.gpg-agent.ssh"),
		ssh,
		bus,
	}
	for _, p := range listed {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		unixDestListen(t, p)
	}
	unrelated := filepath.Join(root, "unrelated.sock")
	unixDestListen(t, unrelated)
	d := newDenyList(denyListPaths(root, 4242, ssh, "unix:path="+bus))
	t.Cleanup(d.Close)
	for _, p := range listed {
		if entry, ok := d.denies(denyStat(t, p)); !ok || entry != p {
			t.Errorf("%s: denied %v by %q", p, ok, entry)
		}
	}
	if entry, ok := d.denies(denyStat(t, unrelated)); ok {
		t.Errorf("an unrelated socket is denied by %q", entry)
	}
	later := filepath.Join(root, "run/user/4242/gnupg/S.later")
	unixDestListen(t, later)
	if _, ok := d.denies(denyStat(t, later)); !ok {
		t.Error("a gpg-agent socket created after the list was built is not denied")
	}
}

func TestDenyListFollowsRestartsAndHeldSockets(t *testing.T) {
	dir := brkRealDir(t)
	restarted, moved := filepath.Join(dir, "restarted.sock"), filepath.Join(dir, "moved.sock")
	first := unixDestListen(t, restarted)
	unixDestListen(t, moved)
	d := newDenyList([]string{restarted, moved}, nil)
	t.Cleanup(d.Close)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(restarted); err != nil {
		t.Fatal(err)
	}
	unixDestListen(t, restarted)
	if _, ok := d.denies(denyStat(t, restarted)); !ok {
		t.Error("a restarted service's new socket at the listed path is not denied")
	}

	away := filepath.Join(dir, "away.sock")
	if err := os.Rename(moved, away); err != nil {
		t.Fatal(err)
	}
	if entry, ok := d.denies(denyStat(t, away)); !ok || entry != moved {
		t.Errorf("a socket held since the list was built, moved off its path: denied %v by %q", ok, entry)
	}
}
