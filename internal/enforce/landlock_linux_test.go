package enforce

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

type fakeNode struct {
	mode   fs.FileMode
	target string
}

type fakeFS struct {
	nodes map[string]fakeNode
	fail  map[string]error
}

func newFakeFS(spec ...string) *fakeFS {
	f := &fakeFS{nodes: map[string]fakeNode{"/": {mode: fs.ModeDir}}, fail: map[string]error{}}
	for _, s := range spec {
		node := fakeNode{}
		path, target, isLink := strings.Cut(s, " -> ")
		switch {
		case isLink:
			node = fakeNode{mode: fs.ModeSymlink, target: target}
		case strings.HasSuffix(path, "/"):
			node.mode = fs.ModeDir
		}
		path = filepath.Clean(path)
		f.nodes[path] = node
		for dir := filepath.Dir(path); dir != "/"; dir = filepath.Dir(dir) {
			if _, ok := f.nodes[dir]; !ok {
				f.nodes[dir] = fakeNode{mode: fs.ModeDir}
			}
		}
	}
	return f
}

type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

func notExist(p string) error { return &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist} }

func (f *fakeFS) eval(p string, depth int) (string, error) {
	if depth > 40 {
		return "", &fs.PathError{Op: "lstat", Path: p, Err: syscall.ELOOP}
	}
	cur := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		next := filepath.Join(cur, part)
		n, ok := f.nodes[next]
		if !ok {
			return "", notExist(next)
		}
		if n.mode&fs.ModeSymlink != 0 {
			resolved, err := f.eval(n.target, depth+1)
			if err != nil {
				return "", err
			}
			next = resolved
		}
		cur = next
	}
	return cur, nil
}

func (f *fakeFS) EvalSymlinks(p string) (string, error) {
	if err := f.fail["eval "+p]; err != nil {
		return "", err
	}
	return f.eval(p, 0)
}

func (f *fakeFS) Stat(p string) (fs.FileInfo, error) {
	if err := f.fail["stat "+p]; err != nil {
		return nil, err
	}
	t, err := f.eval(p, 0)
	if err != nil {
		return nil, err
	}
	return fakeInfo{name: filepath.Base(t), mode: f.nodes[t].mode}, nil
}

func (f *fakeFS) Lstat(p string) (fs.FileInfo, error) {
	n, ok := f.nodes[p]
	if !ok {
		return nil, notExist(p)
	}
	return fakeInfo{name: filepath.Base(p), mode: n.mode}, nil
}

func (f *fakeFS) Readlink(p string) (string, error) {
	n, ok := f.nodes[p]
	if !ok || n.mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: syscall.EINVAL}
	}
	return n.target, nil
}

func (f *fakeFS) ReadDir(p string) ([]fs.DirEntry, error) {
	if err := f.fail["readdir "+p]; err != nil {
		return nil, err
	}
	if n, ok := f.nodes[p]; !ok || !n.mode.IsDir() {
		return nil, notExist(p)
	}
	var names []string
	for k := range f.nodes {
		if k != "/" && filepath.Dir(k) == p {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	out := make([]fs.DirEntry, len(names))
	for i, k := range names {
		out[i] = fs.FileInfoToDirEntry(fakeInfo{name: filepath.Base(k), mode: f.nodes[k].mode.Type()})
	}
	return out, nil
}

const (
	wantD  = landlock.AccessFSSet(llsys.AccessFSReadDir)
	wantRf = landlock.AccessFSSet(llsys.AccessFSReadFile | llsys.AccessFSExecute)
	wantR  = wantRf | wantD
	wantW  = landlock.AccessFSSet(llsys.AccessFSWriteFile | llsys.AccessFSTruncate |
		llsys.AccessFSMakeReg | llsys.AccessFSMakeDir | llsys.AccessFSMakeSym | llsys.AccessFSMakeFifo |
		llsys.AccessFSMakeSock | llsys.AccessFSRemoveFile | llsys.AccessFSRemoveDir | llsys.AccessFSRefer)
	wantN   = landlock.AccessFSSet(llsys.AccessFSWriteFile)
	wantRWf = wantRf | landlock.AccessFSSet(llsys.AccessFSWriteFile|llsys.AccessFSTruncate)
)

var ruleNames = map[landlock.AccessFSSet]string{
	wantD:          "D",
	wantR:          "R",
	wantRf:         "Rf",
	wantR | wantW:  "RW",
	wantRWf:        "RWf",
	wantN:          "N",
	wantRf | wantN: "RfN",
}

func ruleLabels(rules []pathRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		name, ok := ruleNames[r.Access]
		if !ok {
			name = r.Access.String()
		}
		out[i] = r.Path + ":" + name
	}
	return out
}

var baseTree = []string{"/etc/passwd", "/etc/hosts", "/dev/null", "/dev/shm/", "/home/u/.codemeld/", "/home/u/notes", "/home/v/", "/tmp/"}

const floor = "/home/u/.codemeld"

func planPolicy(blocked ...string) Policy {
	return Policy{Mode: ModePlan, BlockedPaths: append([]string{floor}, blocked...)}
}

func autoPolicy(roots, noWrite []string, blocked ...string) Policy {
	return Policy{Mode: ModeAutoEdits, BlockedPaths: append([]string{floor}, blocked...), WriteRoots: roots, NoWritePaths: noWrite, TmpDir: "/tmp"}
}

func TestLandlockRules(t *testing.T) {
	cases := []struct {
		name   string
		extra  []string
		policy Policy
		want   []string
	}{
		{
			name:   "blocked folder with every ancestor read-dir only",
			policy: planPolicy(),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:R", "/dev/null:N"},
		},
		{
			name:   "blocked file",
			policy: planPolicy("/etc/passwd"),
			want:   []string{"/:D", "/dev:R", "/etc:D", "/etc/hosts:Rf", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:R", "/dev/null:N"},
		},
		{
			name:   "two blocked paths under one folder",
			policy: planPolicy("/home/u/notes"),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/v:R", "/tmp:R", "/dev/null:N"},
		},
		{
			name:   "missing blocked path pins its existing parent",
			extra:  []string{"/home/v/x"},
			policy: planPolicy("/home/v/missing/deep"),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:D", "/home/v/x:Rf", "/tmp:R", "/dev/null:N"},
		},
		{
			name:   "blocked symlink carves written and resolved forms",
			extra:  []string{"/home/u/link -> /home/u/real", "/home/u/real/f"},
			policy: planPolicy("/home/u/link", "/home/u/real"),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:R", "/dev/null:N"},
		},
		{
			name:   "dev null blocked directly",
			policy: planPolicy("/dev/null"),
			want:   []string{"/:D", "/dev:D", "/dev/shm:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:R"},
		},
		{
			name:   "dev null blocked by an ancestor",
			policy: planPolicy("/dev"),
			want:   []string{"/:D", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:R"},
		},
		{
			name:   "neighbor symlinks to a blocked folder, to its ancestor, and dangling",
			extra:  []string{"/a -> /home/u", "/home/u/s -> /home/u/.codemeld", "/home/u/dangling -> /nowhere"},
			policy: planPolicy(),
			want:   []string{"/:D", "/home/u:D", "/home/u/notes:Rf", "/dev:R", "/etc:R", "/home:D", "/home/v:R", "/tmp:R", "/dev/null:N"},
		},
		{
			name:   "auto_edits tmp dir",
			policy: autoPolicy(nil, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "blocked path inside a write root, neighbor symlink out of the root",
			extra:  []string{"/home/v/p/src/", "/home/v/p/secret", "/home/v/p/out -> /etc"},
			policy: autoPolicy([]string{"/home/v/p"}, nil, "/home/v/p/secret"),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:D", "/home/v/p:D", "/home/v/p/src:RW", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "write root inside a blocked path",
			extra:  []string{"/home/u/.codemeld/x/"},
			policy: autoPolicy([]string{"/home/u/.codemeld/x"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "project .codemeld under a write root above the project",
			extra:  []string{"/home/v/p/.codemeld/", "/home/v/p/a.go"},
			policy: autoPolicy([]string{"/home/v"}, []string{"/home/v/p/.codemeld"}),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/p/a.go:RWf"},
		},
		{
			name:   "project .codemeld under the temp folder",
			extra:  []string{"/tmp/p/.codemeld/", "/tmp/p/a.go"},
			policy: autoPolicy(nil, []string{"/tmp/p/.codemeld"}),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:R", "/dev/null:N", "/tmp/p/a.go:RWf"},
		},
		{
			name:   "write root equal to /dev/shm",
			policy: autoPolicy([]string{"/dev/shm"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "write root above /dev/shm",
			policy: autoPolicy([]string{"/dev"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:RWf"},
		},
		{
			name:   "write root strictly beneath /dev/shm",
			extra:  []string{"/dev/shm/x/"},
			policy: autoPolicy([]string{"/dev/shm/x"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/dev/shm/x:RW"},
		},
		{
			name:   "write root that is a regular file",
			extra:  []string{"/home/v/f"},
			policy: autoPolicy([]string{"/home/v/f"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/f:RWf"},
		},
		{
			name:   "write-root symlink into a blocked path",
			extra:  []string{"/home/v/l -> /home/u/.codemeld"},
			policy: autoPolicy([]string{"/home/v/l"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "write-root symlink to a folder holding the project .codemeld",
			extra:  []string{"/home/v/l -> /home/v/p", "/home/v/p/.codemeld/", "/home/v/p/a/"},
			policy: autoPolicy([]string{"/home/v/l"}, []string{"/home/v/p/.codemeld"}),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/p/a:RW"},
		},
		{
			name:   "write-root symlink to a folder holding /dev/shm",
			extra:  []string{"/home/v/d -> /dev"},
			policy: autoPolicy([]string{"/home/v/d"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:RWf"},
		},
		{
			name:   "write root inside another write root",
			extra:  []string{"/home/v/p/sub/"},
			policy: autoPolicy([]string{"/home/v/p/sub", "/home/v/p"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/p:RW"},
		},
		{
			name:   "write root inside the temp folder",
			extra:  []string{"/tmp/d/"},
			policy: autoPolicy([]string{"/tmp/d"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "regular-file write root inside another write root",
			extra:  []string{"/home/v/p/f"},
			policy: autoPolicy([]string{"/home/v/p/f", "/home/v/p"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/p:RW"},
		},
		{
			name:   "duplicate write roots",
			extra:  []string{"/home/v/p/"},
			policy: autoPolicy([]string{"/home/v/p", "/tmp", "/home/v/p"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/p:RW"},
		},
		{
			name:   "sibling write roots sharing a name prefix",
			extra:  []string{"/home/v/p/", "/home/v/pq/"},
			policy: autoPolicy([]string{"/home/v/pq", "/home/v/p"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/pq:RW", "/home/v/p:RW"},
		},
		{
			name:   "nested write root now a symlink to an outside folder",
			extra:  []string{"/home/v/p/sub -> /etc"},
			policy: autoPolicy([]string{"/home/v/p", "/home/v/p/sub"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/home/v/p:RW"},
		},
		{
			name:   "write root in the temp folder now a symlink to an outside folder",
			extra:  []string{"/tmp/d -> /home/v"},
			policy: autoPolicy([]string{"/tmp/d"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N"},
		},
		{
			name:   "write root beneath /dev/shm with an outer root above /dev/shm",
			extra:  []string{"/dev/shm/x/"},
			policy: autoPolicy([]string{"/dev", "/dev/shm/x"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:RWf", "/dev/shm/x:RW"},
		},
		{
			name:   "write root beneath /dev/shm with /dev/shm as a write root",
			extra:  []string{"/dev/shm/x/"},
			policy: autoPolicy([]string{"/dev/shm", "/dev/shm/x"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/dev/shm/x:RW"},
		},
		{
			name:   "write root nested strictly beneath /dev/shm",
			extra:  []string{"/dev/shm/x/y/"},
			policy: autoPolicy([]string{"/dev/shm/x/y", "/dev/shm/x"}, nil),
			want:   []string{"/:D", "/dev:R", "/etc:R", "/home:D", "/home/u:D", "/home/u/notes:Rf", "/home/v:R", "/tmp:RW", "/dev/null:N", "/dev/shm/x:RW"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rules, err := landlockRules(c.policy, newFakeFS(append(append([]string{}, baseTree...), c.extra...)...))
			if err != nil {
				t.Fatal(err)
			}
			if got := ruleLabels(rules); !reflect.DeepEqual(got, c.want) {
				t.Errorf("rules\n got %q\nwant %q", got, c.want)
			}
			for _, r := range rules {
				if r.Access&(llsys.AccessFSMakeChar|llsys.AccessFSMakeBlock) != 0 {
					t.Errorf("%s grants make_char or make_block", r.Path)
				}
				allowed := wantR
				if r.Path == "/dev/null" {
					allowed |= wantN
				}
				if c.policy.Mode == ModePlan && r.Access&^allowed != 0 {
					t.Errorf("plan rule %s carries %v", r.Path, r.Access)
				}
			}
		})
	}
}

func TestLandlockRulesOuterWriteRoot(t *testing.T) {
	cases := []struct {
		name       string
		extra      []string
		blocked    []string
		noWrite    []string
		root       string
		wantWrites []string
	}{
		{
			name:       "plain write root",
			root:       "/tmp",
			wantWrites: []string{"/s/private:RW", "/tmp:RW"},
		},
		{
			name:       "blocked path inside the write root",
			extra:      []string{"/tmp/keep/", "/tmp/secret"},
			blocked:    []string{"/tmp/secret"},
			root:       "/tmp",
			wantWrites: []string{"/s/private:RW", "/tmp/keep:RW"},
		},
		{
			name:       "project .codemeld under the write root",
			extra:      []string{"/tmp/p/.codemeld/", "/tmp/p/a.go"},
			noWrite:    []string{"/tmp/p/.codemeld"},
			root:       "/tmp",
			wantWrites: []string{"/s/private:RW", "/tmp/p/a.go:RWf"},
		},
		{
			name:       "write root equal to /dev/shm",
			root:       "/dev/shm",
			wantWrites: []string{"/s/private:RW"},
		},
		{
			name:       "write root above /dev/shm",
			root:       "/dev",
			wantWrites: []string{"/dev/null:RWf", "/s/private:RW"},
		},
		{
			name:       "write root inside the fixed floor",
			extra:      []string{"/home/u/.codemeld/t/"},
			root:       "/home/u/.codemeld/t",
			wantWrites: []string{"/s/private:RW"},
		},
		{
			name:       "home under the write root",
			extra:      []string{"/tmp/h/.codemeld/", "/tmp/h/notes", "/tmp/h/work/", "/tmp/other/"},
			blocked:    []string{"/tmp/h/.codemeld"},
			root:       "/tmp",
			wantWrites: []string{"/s/private:RW", "/tmp/h/notes:RWf", "/tmp/h/work:RW", "/tmp/other:RW"},
		},
	}
	writes := func(rules []pathRule) []string {
		var out []pathRule
		for _, r := range rules {
			if r.Access&(llsys.AccessFSMakeReg|llsys.AccessFSTruncate) != 0 {
				out = append(out, r)
			}
		}
		labels := ruleLabels(out)
		sort.Strings(labels)
		return labels
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := append(append([]string{}, baseTree...), "/s/private/")
			blocked := append([]string{floor}, c.blocked...)
			declared := Policy{Mode: ModeAutoEdits, BlockedPaths: blocked, NoWritePaths: c.noWrite, TmpDir: "/s/private", WriteRoots: []string{c.root}}
			asTmp := Policy{Mode: ModeAutoEdits, BlockedPaths: blocked, NoWritePaths: c.noWrite, TmpDir: c.root, WriteRoots: []string{"/s/private"}}
			got, err := landlockRules(declared, newFakeFS(append(tree, c.extra...)...))
			if err != nil {
				t.Fatal(err)
			}
			want, err := landlockRules(asTmp, newFakeFS(append(tree, c.extra...)...))
			if err != nil {
				t.Fatal(err)
			}
			gotLabels, wantLabels := ruleLabels(got), ruleLabels(want)
			sort.Strings(gotLabels)
			sort.Strings(wantLabels)
			if !reflect.DeepEqual(gotLabels, wantLabels) {
				t.Errorf("write root rules differ from the same folder as tmp_dir\n got %q\nwant %q", gotLabels, wantLabels)
			}
			if w := writes(got); !reflect.DeepEqual(w, c.wantWrites) {
				t.Errorf("write rules\n got %q\nwant %q", w, c.wantWrites)
			}
		})
	}
}

type splitFS struct {
	fake *fakeFS
	real string
}

func (s splitFS) pick(p string) fsView {
	if within(p, s.real) {
		return osFS{}
	}
	return s.fake
}

func (s splitFS) ReadDir(p string) ([]fs.DirEntry, error) { return s.pick(p).ReadDir(p) }
func (s splitFS) Stat(p string) (fs.FileInfo, error)      { return s.pick(p).Stat(p) }
func (s splitFS) EvalSymlinks(p string) (string, error)   { return s.pick(p).EvalSymlinks(p) }
func (s splitFS) Lstat(p string) (fs.FileInfo, error)     { return s.pick(p).Lstat(p) }
func (s splitFS) Readlink(p string) (string, error)       { return s.pick(p).Readlink(p) }

func TestLandlockRulesCarveMissingNoWriteDestinations(t *testing.T) {
	cases := []struct {
		name    string
		tree    []string
		roots   []string
		noWrite string
		dest    string
		want    []string
	}{
		{
			name:    "missing exclusion beneath a symlinked parent",
			tree:    []string{"session/keep", "session/sub/x", "project/link -> session/sub"},
			noWrite: "project/link/.codemeld",
			dest:    "session/sub/.codemeld",
			want:    []string{"session/keep:RWf", "session/sub/x:RWf"},
		},
		{
			name:    "dangling final .codemeld symlink into the temp folder",
			tree:    []string{"session/keep", "session/sub/x", "project/.codemeld -> session/state"},
			noWrite: "project/.codemeld",
			dest:    "session/state",
			want:    []string{"session/keep:RWf", "session/sub:RW"},
		},
		{
			name:    "ordinary missing .codemeld",
			tree:    []string{"session/keep", "project/a.go"},
			roots:   []string{"project"},
			noWrite: "project/.codemeld",
			dest:    "project/.codemeld",
			want:    []string{"project/a.go:RWf", "session:RW"},
		},
	}
	views := map[string]func(t *testing.T, tree []string) (string, fsView){
		"fake": func(t *testing.T, tree []string) (string, fsView) {
			spec := append([]string{}, baseTree...)
			for _, e := range tree {
				path, target, isLink := strings.Cut(e, " -> ")
				if isLink {
					spec = append(spec, "/r/"+path+" -> /r/"+target)
				} else {
					spec = append(spec, "/r/"+path)
				}
			}
			return "/r", newFakeFS(spec...)
		},
		"real": func(t *testing.T, tree []string) (string, fsView) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range tree {
				path, target, isLink := strings.Cut(e, " -> ")
				full := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if isLink {
					err = os.Symlink(filepath.Join(root, target), full)
				} else {
					err = os.WriteFile(full, nil, 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			return root, splitFS{fake: newFakeFS(append(append([]string{}, baseTree...), root+"/")...), real: root}
		},
	}
	for _, c := range cases {
		for viewName, mk := range views {
			t.Run(c.name+"/"+viewName, func(t *testing.T) {
				root, view := mk(t, c.tree)
				var roots []string
				for _, r := range c.roots {
					roots = append(roots, filepath.Join(root, r))
				}
				p := Policy{Mode: ModeAutoEdits, BlockedPaths: []string{floor}, WriteRoots: roots,
					NoWritePaths: []string{filepath.Join(root, c.noWrite)}, TmpDir: filepath.Join(root, "session")}
				rules, err := landlockRules(p, view)
				if err != nil {
					t.Fatal(err)
				}
				var writes []pathRule
				for _, r := range rules {
					if r.Access&wantW == 0 || !within(r.Path, root) {
						continue
					}
					writes = append(writes, pathRule{Path: strings.TrimPrefix(r.Path, root+"/"), Access: r.Access})
					if within(filepath.Join(root, c.dest), r.Path) {
						t.Errorf("write rule %s covers %s", r.Path, c.dest)
					}
				}
				if got := ruleLabels(writes); !reflect.DeepEqual(got, c.want) {
					t.Errorf("write rules\n got %q\nwant %q", got, c.want)
				}
			})
		}
	}
}

func TestLandlockRulesReturnsNonMissingErrors(t *testing.T) {
	for _, key := range []string{"readdir /home", "eval /home/u/link", "stat /home/u/real", "eval /tmp"} {
		f := newFakeFS(append(append([]string{}, baseTree...), "/home/u/link -> /home/u/real", "/home/u/real/")...)
		f.fail[key] = &fs.PathError{Op: "x", Path: key, Err: syscall.EACCES}
		if _, err := landlockRules(autoPolicy(nil, nil), f); !errors.Is(err, syscall.EACCES) {
			t.Errorf("%s: err = %v, want EACCES", key, err)
		}
	}
}

func stubLandlock(t *testing.T, abi int, abiErr error) *int {
	t.Helper()
	calls := 0
	oldABI, oldRestrict := landlockABI, restrictPaths
	t.Cleanup(func() { landlockABI, restrictPaths = oldABI, oldRestrict })
	landlockABI = func() (int, error) { return abi, abiErr }
	restrictPaths = func(...landlock.Rule) error { calls++; return nil }
	return &calls
}

func TestApplyLandlockRefusesOldABI(t *testing.T) {
	calls := stubLandlock(t, 2, nil)
	err := applyLandlock(planPolicy())
	if err == nil || err.Error() != "landlock ABI 2 < 3; sandbox needs Landlock ABI 3 or newer, first shipped in Linux 6.2" {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix("codemeld confinement: landlock: "+err.Error(), "codemeld confinement: landlock: landlock ABI") {
		t.Errorf("helper-prefixed reason lost the bootstrap skip marker: %v", err)
	}
	if *calls != 0 {
		t.Errorf("restricted %d times", *calls)
	}
}

func TestApplyLandlockReportsProbeError(t *testing.T) {
	calls := stubLandlock(t, -1, syscall.ENOSYS)
	err := applyLandlock(planPolicy())
	if err == nil || !strings.Contains(err.Error(), syscall.ENOSYS.Error()) {
		t.Errorf("err = %v", err)
	}
	if *calls != 0 {
		t.Errorf("restricted %d times", *calls)
	}
}

func TestLandlockRulesCarveResolvedBlockedPaths(t *testing.T) {
	f := newFakeFS("/dev/null", "/home/link -> /home/real", "/home/real/u/.codemeld/", "/home/real/u/notes", "/home/other/")
	rules, err := landlockRules(Policy{Mode: ModePlan, BlockedPaths: []string{"/home/link/u/.codemeld"}}, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		for _, blocked := range []string{"/home/real/u/.codemeld", "/home/link/u/.codemeld"} {
			if within(blocked, r.Path) && r.Access != accessReadDir {
				t.Errorf("rule %s:%v covers %s", r.Path, r.Access, blocked)
			}
		}
	}
	if !slices.ContainsFunc(rules, func(r pathRule) bool { return r.Path == "/home/real/u/notes" }) {
		t.Errorf("rules %v lost the readable sibling", ruleLabels(rules))
	}
	loop := newFakeFS("/home/a -> /home/b", "/home/b -> /home/a")
	if _, err := landlockRules(Policy{Mode: ModePlan, BlockedPaths: []string{"/home/a/x"}}, loop); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("symlink loop: err = %v, want ELOOP", err)
	}
}
