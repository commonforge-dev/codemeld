package enforce

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

type refusalFx struct {
	base, blocked, root, tmp, outside string
	policy                            Policy
}

func newRefusalFx(t *testing.T) refusalFx {
	t.Helper()
	base, err := os.MkdirTemp("/var/tmp", "codemeld-refusal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(base, "outside", "closed"), 0o700)
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("fixture: removing %s: %v", base, err)
		}
	})
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatal(err)
	}
	fx := refusalFx{base: base, blocked: filepath.Join(base, "blocked"), root: filepath.Join(base, "root"),
		tmp: filepath.Join(base, "tmp"), outside: filepath.Join(base, "outside")}
	for _, d := range []string{fx.blocked, filepath.Join(fx.root, "sub"), filepath.Join(fx.root, ".codemeld"), filepath.Join(fx.root, ".hg"),
		fx.tmp, filepath.Join(fx.outside, "dir"), filepath.Join(fx.outside, "closed")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"src", "r"} {
		if err := os.WriteFile(filepath.Join(fx.outside, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(fx.outside, "r"), filepath.Join(fx.outside, "sym")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(fx.outside, "missing"), filepath.Join(fx.outside, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(fx.outside, "closed"), 0); err != nil {
		t.Fatal(err)
	}
	fx.policy = Policy{
		Mode: ModeAutoEdits, BlockedPaths: []string{fx.blocked}, WriteRoots: []string{fx.root},
		NoWritePaths: []string{filepath.Join(fx.root, ".codemeld"), filepath.Join(fx.root, ".hg")}, TmpDir: fx.tmp,
	}
	return fx
}

func watched(name string, paths ...string) WatchedCall {
	c := WatchedCall{Syscall: name, Process: "proc"}
	for _, p := range paths {
		c.Paths = append(c.Paths, WatchedPath{Path: p})
	}
	return c
}

func flagged(c WatchedCall, flags uint32) WatchedCall {
	c.Flags = flags
	return c
}

func how(path string, h WatchedOpenHow) WatchedCall {
	c := watched("openat2", path)
	c.OpenHow = &h
	return c
}

func collect(t *testing.T, p Policy, calls ...WatchedCall) ([]FileRefusal, int) {
	t.Helper()
	c, err := NewRefusalCollector(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		if call.gate == nil {
			call.gate = &watchGate{open: true}
		}
		c.Watch(call)
	}
	return c.Report()
}

func readOnlyMount(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 5 && (fields[5] == "ro" || strings.HasPrefix(fields[5], "ro,")) &&
			!strings.Contains(fields[4], `\`) && !strings.HasPrefix(fields[4], "/proc") {
			if info, err := os.Stat(fields[4]); err == nil && info.IsDir() {
				return fields[4]
			}
		}
	}
	return ""
}

func TestRefusalCollectorPredictsLandlockRefusals(t *testing.T) {
	fx := newRefusalFx(t)
	out := func(name string) string { return filepath.Join(fx.outside, name) }
	candidate := func(path, folder string) FileRefusal {
		return FileRefusal{Path: path, Process: "proc", Candidate: folder}
	}
	refused := func(path, reason string) FileRefusal {
		return FileRefusal{Path: path, Process: "proc", Reason: reason}
	}
	create := uint32(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL)
	shmDirect := "/dev/shm/codemeld-refusal-direct"
	unsupported := fmt.Errorf("%w: trailing slash", ErrWatchUnsupported)
	type row struct {
		calls    []WatchedCall
		want     []FileRefusal
		unjudged int
	}
	one := func(c WatchedCall, want ...FileRefusal) row { return row{calls: []WatchedCall{c}, want: want} }
	unjudged := func(c WatchedCall) row { return row{calls: []WatchedCall{c}, unjudged: 1} }
	rows := map[string]row{
		"mkdir outside the write roots": one(watched("mkdirat", out("new")), candidate(out("new"), fx.outside)),
		"mkdir in the temp folder":      one(watched("mkdirat", filepath.Join(fx.tmp, "new"))),
		"create in .codemeld": one(flagged(watched("openat", filepath.Join(fx.root, ".codemeld", "x")), create),
			refused(filepath.Join(fx.root, ".codemeld", "x"), "no-write path")),
		"create in .hg": one(flagged(watched("openat", filepath.Join(fx.root, ".hg", "x")), create),
			refused(filepath.Join(fx.root, ".hg", "x"), "no-write path")),
		"create in a blocked folder": one(flagged(watched("openat", filepath.Join(fx.blocked, "x")), create),
			refused(filepath.Join(fx.blocked, "x"), "blocked path")),
		"new entry beside a protected path": one(watched("mkdirat", filepath.Join(fx.root, "new")),
			refused(filepath.Join(fx.root, "new"), fx.root+" holds a blocked or no-write path")),
		"mkdir of an existing folder":     one(watched("mkdirat", fx.outside)),
		"O_TRUNC on /dev/null":            one(flagged(watched("openat", "/dev/null"), unix.O_WRONLY|unix.O_TRUNC)),
		"truncate outside":                one(watched("truncate", out("r")), candidate(out("r"), fx.outside)),
		"rename from outside":             one(watched("renameat2", out("src"), filepath.Join(fx.root, "sub", "moved")), candidate(out("src"), fx.outside)),
		"a refused path is listed once":   {calls: []WatchedCall{watched("mkdirat", out("new")), watched("mkdir", out("new"))}, want: []FileRefusal{candidate(out("new"), fx.outside)}},
		"missing parent":                  one(WatchedCall{Syscall: "mkdirat", Paths: []WatchedPath{{Err: ErrWatchNoParent}}}),
		"missing parent, unmodelled open flags": unjudged(WatchedCall{Syscall: "openat", Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_DIRECTORY, Paths: []WatchedPath{{Err: ErrWatchNoParent}}}),
		"missing parent, RENAME_EXCHANGE":       unjudged(WatchedCall{Syscall: "renameat2", Flags: unix.RENAME_EXCHANGE, Paths: []WatchedPath{{Err: ErrWatchNoParent}, {Path: out("r")}}}),
		"missing parent, unlinkat unknown flag": unjudged(WatchedCall{Syscall: "unlinkat", Flags: 1 << 31, Paths: []WatchedPath{{Err: ErrWatchNoParent}}}),
		"missing parent, linkat AT_EMPTY_PATH":  unjudged(WatchedCall{Syscall: "linkat", Flags: unix.AT_EMPTY_PATH, Paths: []WatchedPath{{Err: ErrWatchNoParent}, {Path: out("linked")}}}),
		"missing parent, mknod of a folder":     unjudged(WatchedCall{Syscall: "mknodat", Mode: unix.S_IFDIR | 0o700, Paths: []WatchedPath{{Err: ErrWatchNoParent}}}),
		"missing parent, unreadable second":     unjudged(WatchedCall{Syscall: "renameat2", Paths: []WatchedPath{{Err: ErrWatchNoParent}, {Err: unix.EFAULT}}}),
		"O_PATH open":                     one(flagged(watched("openat", out("new")), unix.O_PATH|unix.O_WRONLY|unix.O_CREAT)),
		"O_NOFOLLOW on a final symlink":   one(flagged(watched("openat", out("sym")), unix.O_WRONLY|unix.O_NOFOLLOW)),
		"write-intent open of a folder":   one(flagged(watched("openat", fx.outside), unix.O_WRONLY)),
		"read-only openat2":               one(how(out("r"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_RDONLY, Resolve: unix.RESOLVE_IN_ROOT}})),
		"a call no longer handled":        {calls: []WatchedCall{func() WatchedCall { c := watched("mkdirat", out("new")); c.gate = &watchGate{}; return c }()}},
		"unlink of a folder":              unjudged(watched("unlink", out("dir"))),
		"unlinkat of a folder":            unjudged(watched("unlinkat", out("dir"))),
		"rename into its own descendant":  unjudged(watched("renameat2", out("dir"), filepath.Join(out("dir"), "inner"))),
		"unreadable path":                 unjudged(WatchedCall{Syscall: "mkdirat", Paths: []WatchedPath{{Err: unix.EFAULT}}}),
		"unmodelled path shape":           unjudged(WatchedCall{Syscall: "unlinkat", Paths: []WatchedPath{{Err: unsupported}}}),
		"O_TMPFILE":                       unjudged(flagged(watched("openat", fx.outside), unix.O_TMPFILE|unix.O_WRONLY)),
		"O_DIRECTORY":                     unjudged(flagged(watched("openat", out("new")), unix.O_WRONLY|unix.O_CREAT|unix.O_DIRECTORY)),
		"access mode 3":                   unjudged(flagged(watched("openat", out("r")), unix.O_ACCMODE)),
		"dangling final symlink":          unjudged(flagged(watched("openat", out("dangling")), unix.O_WRONLY|unix.O_CREAT)),
		"inspection error":                unjudged(watched("mkdirat", filepath.Join(out("closed"), "x"))),
		"remove inspection error":         unjudged(watched("unlinkat", filepath.Join(out("closed"), "x"))),
		"rename source inspection error":  unjudged(watched("renameat2", filepath.Join(out("closed"), "x"), out("moved"))),
		"link source inspection error":    unjudged(watched("linkat", filepath.Join(out("closed"), "x"), out("linked"))),
		"remove of an absent file":        one(watched("unlinkat", out("missing"))),
		"rename of an absent source":      one(watched("renameat2", out("missing"), out("moved"))),
		"openat2 unreadable":              unjudged(how(out("new"), WatchedOpenHow{Err: unix.EFAULT})),
		"openat2 resolve":                 unjudged(how(out("new"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT, Resolve: unix.RESOLVE_BENEATH}})),
		"openat2 extension":               unjudged(how(out("new"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT}, ExtensionNonzero: true})),
		"openat2 high flags":              unjudged(how(out("new"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | 1<<40}})),
		"openat2 mode without create":     unjudged(how(out("r"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_WRONLY, Mode: 0o600}})),
		"openat2 O_PATH on an existing file": one(how(out("r"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_PATH | unix.O_WRONLY}})),
		"openat2 unknown flag":               unjudged(how(out("r"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_WRONLY | 1<<31}})),
		"renameat2 unknown flag":             unjudged(flagged(watched("renameat2", out("src"), out("moved")), 1<<31)),
		"mkdir under a file":                 unjudged(watched("mkdirat", filepath.Join(out("r"), "new"))),
		"RENAME_EXCHANGE":                 unjudged(flagged(watched("renameat2", out("src"), out("r")), unix.RENAME_EXCHANGE)),
		"RENAME_WHITEOUT":                 unjudged(flagged(watched("renameat2", out("src"), out("moved")), unix.RENAME_WHITEOUT)),
		"linkat AT_EMPTY_PATH":            unjudged(flagged(watched("linkat", out("src"), out("linked")), unix.AT_EMPTY_PATH)),
		"unlinkat unknown flag":           unjudged(flagged(watched("unlinkat", out("src")), 1<<31)),
		"mknod of a folder":               unjudged(WatchedCall{Syscall: "mknodat", Mode: unix.S_IFDIR | 0o700, Paths: []WatchedPath{{Path: out("new")}}}),
		"unreadable symlink target":       unjudged(WatchedCall{Syscall: "symlinkat", TargetErr: unix.EFAULT, Paths: []WatchedPath{{Path: out("link")}}}),
		"empty symlink target":            unjudged(watched("symlinkat", out("link"))),
		"negative truncate":               unjudged(WatchedCall{Syscall: "truncate", Length: -1, Paths: []WatchedPath{{Path: out("r")}}}),
		"symlink with a readable target":  one(WatchedCall{Syscall: "symlinkat", Process: "proc", Target: "x", Paths: []WatchedPath{{Path: out("link")}}}, candidate(out("link"), fx.outside)),
		"linkat following a symlink":      one(flagged(watched("linkat", out("sym"), filepath.Join(fx.root, "sub", "linked")), unix.AT_SYMLINK_FOLLOW), candidate(out("r"), fx.outside)),
		"linkat following a dangling one": one(flagged(watched("linkat", out("dangling"), filepath.Join(fx.root, "sub", "linked")), unix.AT_SYMLINK_FOLLOW)),
		"create outside":                  one(flagged(watched("openat", out("x")), create), candidate(out("x"), fx.outside)),
		"create in a write root":          one(flagged(watched("openat", filepath.Join(fx.root, "sub", "ok")), create)),
		"openat2 create outside":          one(how(out("w"), WatchedOpenHow{How: unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT, Mode: 0o600}}), candidate(out("w"), fx.outside)),
		"link from outside":               one(watched("linkat", out("src"), filepath.Join(fx.root, "sub", "linked")), candidate(out("src"), fx.outside)),
		"rmdir outside":                   one(flagged(watched("unlinkat", out("dir")), unix.AT_REMOVEDIR), candidate(out("dir"), fx.outside)),
		"mknod of a character device":     one(WatchedCall{Syscall: "mknodat", Process: "proc", Mode: unix.S_IFCHR | 0o600, Paths: []WatchedPath{{Path: out("new")}}}, refused(out("new"), "no folder grant gives this right")),
		"mknod of a block device":         one(WatchedCall{Syscall: "mknodat", Process: "proc", Mode: unix.S_IFBLK | 0o600, Paths: []WatchedPath{{Path: out("new")}}}, refused(out("new"), "no folder grant gives this right")),
	}
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		rows["new entry directly in /dev/shm"] = one(flagged(watched("openat", shmDirect), create), refused(shmDirect, "/dev/shm itself"))
		shm, err := os.MkdirTemp("/dev/shm", "codemeld-refusal-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(shm) })
		rows["new entry in a /dev/shm subfolder"] = one(flagged(watched("openat", filepath.Join(shm, "x")), create), candidate(filepath.Join(shm, "x"), shm))
		var a, b unix.Statx_t
		if unix.Statx(unix.AT_FDCWD, fx.outside, 0, unix.STATX_MNT_ID, &a) == nil && unix.Statx(unix.AT_FDCWD, "/dev/shm", 0, unix.STATX_MNT_ID, &b) == nil && a.Mnt_id != b.Mnt_id {
			rows["rename across mounts"] = unjudged(watched("renameat2", out("src"), filepath.Join("/dev/shm", "codemeld-refusal-moved")))
		}
	}
	if dev := filepath.Join(fx.root, "sub", "dev"); unix.Mknod(dev, unix.S_IFCHR|0o600, 0) == nil {
		rows["link of a device node to outside"] = one(watched("linkat", dev, out("linked")), refused(out("linked"), "no folder grant gives this right"))
		rows["rename of a device node to outside"] = one(watched("renameat2", dev, out("moved")), refused(out("moved"), "no folder grant gives this right"))
	}
	if ro := readOnlyMount(t); ro != "" {
		rows["mkdir on a read-only mount"] = unjudged(watched("mkdirat", filepath.Join(ro, "codemeld-refusal-new")))
	}
	if os.Geteuid() == 0 {
		for _, name := range []string{"inspection error", "remove inspection error", "rename source inspection error", "link source inspection error"} {
			delete(rows, name)
		}
	}
	for name, r := range rows {
		t.Run(name, func(t *testing.T) {
			got, n := collect(t, fx.policy, r.calls...)
			if !slices.Equal(got, r.want) || n != r.unjudged {
				t.Errorf("refusals %+v with %d not judged, want %+v with %d", got, n, r.want, r.unjudged)
			}
		})
	}
}

func TestRefusalCollectorDeviceRights(t *testing.T) {
	devs := fstest.MapFS{"char": {Mode: fs.ModeDevice | fs.ModeCharDevice}, "block": {Mode: fs.ModeDevice}}
	for name, want := range map[string]landlock.AccessFSSet{"char": llsys.AccessFSMakeChar, "block": llsys.AccessFSMakeBlock} {
		info, err := fs.Stat(devs, name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fileTypeAccess(info, false); got != want {
			t.Errorf("%s device destination right %v, want %v", name, got, want)
		}
	}
}

func TestRefusalCollectorNeverSuggestsTheFilesystemRoot(t *testing.T) {
	entries, err := os.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(entries, func(e os.DirEntry) bool { return e.Type().IsRegular() })
	if i < 0 {
		t.Skip("no regular file directly under /")
	}
	top := "/" + entries[i].Name()
	fx := newRefusalFx(t)
	got, n := collect(t, fx.policy, flagged(watched("openat", top), unix.O_WRONLY))
	want := []FileRefusal{{Path: top, Process: "proc", Reason: "the filesystem root cannot be a writable folder"}}
	if !slices.Equal(got, want) || n != 0 {
		t.Errorf("write to %s: refusals %+v with %d not judged, want %+v with 0", top, got, n, want)
	}
}

func TestRefusalCollectorPlanListsPathsWithoutAGrantCandidate(t *testing.T) {
	fx := newRefusalFx(t)
	var st unix.Stat_t
	if err := unix.Stat(fx.tmp, &st); err != nil {
		t.Fatal(err)
	}
	plan := Policy{Mode: ModePlan, BlockedPaths: []string{fx.blocked}, TmpDir: fx.tmp, TmpDirDev: uint64(st.Dev), TmpDirIno: st.Ino}
	refused := filepath.Join(fx.outside, "new")
	got, n := collect(t, plan, watched("mkdirat", refused), watched("mkdirat", filepath.Join(fx.tmp, "new")),
		watched("mkdirat", filepath.Join(fx.root, "new")))
	want := []FileRefusal{{Path: refused, Process: "proc"}, {Path: filepath.Join(fx.root, "new"), Process: "proc"}}
	if !slices.Equal(got, want) || n != 0 {
		t.Errorf("plan refusals %+v with %d not judged, want %+v with 0", got, n, want)
	}
	if err := os.Rename(fx.tmp, fx.tmp+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fx.tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	inReplacement := filepath.Join(fx.tmp, "new")
	got, n = collect(t, plan, watched("mkdirat", inReplacement))
	if want := []FileRefusal{{Path: inReplacement, Process: "proc"}}; !slices.Equal(got, want) || n != 0 {
		t.Errorf("replaced temp folder: refusals %+v with %d not judged, want %+v with 0", got, n, want)
	}
}
