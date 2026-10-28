package skills

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testMax = 4096

var testReserved = map[string]bool{"help": true, "q": true}

func stub[T any](t *testing.T, target *T, v T) {
	t.Helper()
	old := *target
	*target = v
	t.Cleanup(func() { *target = old })
}

func countReads(t *testing.T) *int {
	t.Helper()
	reads := 0
	real := readLimited
	stub(t, &readLimited, func(f *os.File, limit int64) ([]byte, error) {
		reads++
		return real(f, limit)
	})
	return &reads
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	mkdir(t, filepath.Dir(link))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func valid(name string) string {
	return "---\nname: " + name + "\ndescription: d\n---\nb\n"
}

type layout struct {
	base, home, project, g, p string
}

func newLayout(t *testing.T) layout {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	project := filepath.Join(base, "project")
	mkdir(t, home)
	mkdir(t, project)
	return layout{
		base:    base,
		home:    home,
		project: project,
		g:       filepath.Join(home, ".codemeld", "skills"),
		p:       filepath.Join(project, ".codemeld", "skills"),
	}
}

func (l layout) load(t *testing.T) Set {
	t.Helper()
	done := make(chan Set, 1)
	go func() { done <- Load(l.home, l.project, testReserved, testMax) }()
	select {
	case s := <-done:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("Load did not finish")
		return Set{}
	}
}

func check(t *testing.T, got, want Set) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load:\n got %+v\nwant %+v", got, want)
	}
}

func globalSkill(l layout, name string) Skill {
	return Skill{Name: name, Description: "d", Layer: Global, Folder: filepath.Join(l.g, name), Body: "b\n", ModelInvocable: true}
}

func projectSkill(l layout, name string) Skill {
	return Skill{Name: name, Description: "d", Layer: Project, Folder: filepath.Join(l.p, name), Body: "b\n", ModelInvocable: true}
}

func TestLoadTable(t *testing.T) {
	desc1024 := strings.Repeat("é", 1023) + "語"
	name64 := strings.Repeat("a", 64)
	tests := []struct {
		name  string
		files map[string]string
		want  func(l layout) Set
	}{
		{
			name:  "valid global",
			files: map[string]string{"g/pdf": "---\nname: pdf\ndescription: Fill PDF forms\n---\nUse pdftk.\n"},
			want: func(l layout) Set {
				return Set{Loaded: []Skill{{Name: "pdf", Description: "Fill PDF forms", Layer: Global, Folder: filepath.Join(l.g, "pdf"), Body: "Use pdftk.\n", ModelInvocable: true}}}
			},
		},
		{
			name:  "valid project",
			files: map[string]string{"p/pdf": valid("pdf")},
			want:  func(l layout) Set { return Set{Loaded: []Skill{projectSkill(l, "pdf")}} },
		},
		{
			name:  "missing name takes folder name",
			files: map[string]string{"g/notes": "---\ndescription: d\n---\nb\n"},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, "notes")}} },
		},
		{
			name:  "unknown keys ignored",
			files: map[string]string{"g/lic": "---\nname: lic\nlicense: MIT\ndescription: d\n---\nb\n"},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, "lic")}} },
		},
		{
			name:  "leading BOM stripped",
			files: map[string]string{"g/bom": "\uFEFF" + valid("bom")},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, "bom")}} },
		},
		{
			name:  "CRLF line ends",
			files: map[string]string{"g/crlf": "---\r\nname: crlf\r\ndescription: d\r\n---\r\nb\r\n"},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, "crlf")}} },
		},
		{
			name:  "disable-model-invocation true",
			files: map[string]string{"g/manual": "---\nname: manual\ndescription: d\ndisable-model-invocation: true\n---\nb\n"},
			want: func(l layout) Set {
				s := globalSkill(l, "manual")
				s.ModelInvocable = false
				return Set{Loaded: []Skill{s}}
			},
		},
		{
			name:  "disable-model-invocation false",
			files: map[string]string{"g/auto": "---\nname: auto\ndescription: d\ndisable-model-invocation: false\n---\nb\n"},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, "auto")}} },
		},
		{
			name:  "empty body",
			files: map[string]string{"g/empty": "---\nname: empty\ndescription: d\n---\n"},
			want: func(l layout) Set {
				s := globalSkill(l, "empty")
				s.Body = ""
				return Set{Loaded: []Skill{s}}
			},
		},
		{
			name:  "64 character name",
			files: map[string]string{"g/" + name64: valid(name64)},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, name64)}} },
		},
		{
			name:  "1024 code point trimmed multibyte description",
			files: map[string]string{"g/long": "---\nname: long\ndescription: \"  " + desc1024 + " \\t\"\n---\nb\n"},
			want: func(l layout) Set {
				s := globalSkill(l, "long")
				s.Description = desc1024
				return Set{Loaded: []Skill{s}}
			},
		},
		{
			name:  "1025 code point description",
			files: map[string]string{"g/long": "---\nname: long\ndescription: \"  " + desc1024 + "x  \"\n---\nb\n"},
			want:  skipped("g/long", BadFrontMatter),
		},
		{name: "missing opening delimiter", files: map[string]string{"g/x": "name: x\ndescription: d\n---\nb\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "unterminated front matter", files: map[string]string{"g/x": "---\nname: x\ndescription: d\nb\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "duplicate key", files: map[string]string{"g/x": "---\nname: x\nname: x\ndescription: d\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "invalid yaml", files: map[string]string{"g/x": "---\nname: [\ndescription: d\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "front matter not a mapping", files: map[string]string{"g/x": "---\n- a\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "non-boolean disable-model-invocation", files: map[string]string{"g/x": "---\nname: x\ndescription: d\ndisable-model-invocation: \"true\"\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "null disable-model-invocation", files: map[string]string{"g/x": "---\nname: x\ndescription: d\ndisable-model-invocation: null\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "tilde disable-model-invocation", files: map[string]string{"g/x": "---\nname: x\ndescription: d\ndisable-model-invocation: ~\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "empty disable-model-invocation", files: map[string]string{"g/x": "---\nname: x\ndescription: d\ndisable-model-invocation:\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "non-string description", files: map[string]string{"g/x": "---\nname: x\ndescription: [a]\n---\n"}, want: skipped("g/x", BadFrontMatter)},
		{name: "trailing hyphen name", files: map[string]string{"g/pdf-": valid("pdf-")}, want: skipped("g/pdf-", BadName)},
		{name: "double hyphen name", files: map[string]string{"g/a--b": valid("a--b")}, want: skipped("g/a--b", BadName)},
		{name: "uppercase name", files: map[string]string{"g/Pdf": valid("Pdf")}, want: skipped("g/Pdf", BadName)},
		{name: "65 character name", files: map[string]string{"g/" + name64 + "a": valid(name64 + "a")}, want: skipped("g/"+name64+"a", BadName)},
		{name: "bad folder name without name", files: map[string]string{"g/Bad_Folder": "---\ndescription: d\n---\n"}, want: skipped("g/Bad_Folder", BadName)},
		{name: "name differs from folder", files: map[string]string{"g/one": valid("two")}, want: skipped("g/one", NameMismatch)},
		{name: "missing description", files: map[string]string{"g/x": "---\nname: x\n---\n"}, want: skipped("g/x", MissingDescription)},
		{name: "blank description", files: map[string]string{"g/x": "---\nname: x\ndescription: \"  \"\n---\n"}, want: skipped("g/x", MissingDescription)},
		{name: "reserved name", files: map[string]string{"g/help": valid("help")}, want: skipped("g/help", BuiltinClash)},
		{name: "reserved alias", files: map[string]string{"p/q": valid("q")}, want: skipped("p/q", BuiltinClash)},
		{name: "too large", files: map[string]string{"g/big": valid("big") + strings.Repeat("x", testMax)}, want: skipped("g/big", TooLarge)},
		{
			name:  "precedence: size before front matter",
			files: map[string]string{"g/big": "no front matter" + strings.Repeat("x", testMax)},
			want:  skipped("g/big", TooLarge),
		},
		{
			name:  "precedence: type before name shape",
			files: map[string]string{"g/x": "---\nname: Bad_Name\ndisable-model-invocation: yes\n---\n"},
			want:  skipped("g/x", BadFrontMatter),
		},
		{
			name:  "precedence: null disable-model-invocation before name shape",
			files: map[string]string{"g/x": "---\nname: Bad_Name\ndisable-model-invocation: null\n---\n"},
			want:  skipped("g/x", BadFrontMatter),
		},
		{
			name:  "precedence: name shape before equality and description",
			files: map[string]string{"g/other": "---\nname: Bad_Name\n---\n"},
			want:  skipped("g/other", BadName),
		},
		{
			name:  "precedence: name equality before description",
			files: map[string]string{"g/other": "---\nname: help\n---\n"},
			want:  skipped("g/other", NameMismatch),
		},
		{
			name:  "precedence: description before reserved",
			files: map[string]string{"g/help": "---\nname: help\n---\n"},
			want:  skipped("g/help", MissingDescription),
		},
		{
			name:  "precedence: overlong description before reserved",
			files: map[string]string{"g/help": "---\nname: help\ndescription: " + desc1024 + "x\n---\n"},
			want:  skipped("g/help", BadFrontMatter),
		},
		{
			name:  "valid project overrides global",
			files: map[string]string{"g/foo": valid("foo"), "p/foo": valid("foo")},
			want: func(l layout) Set {
				return Set{Loaded: []Skill{projectSkill(l, "foo")}, Skipped: []Skipped{{filepath.Join(l.g, "foo"), OverriddenByProject}}}
			},
		},
		{
			name:  "invalid project keeps global",
			files: map[string]string{"g/foo": valid("foo"), "p/foo": "---\nname: foo\n---\n"},
			want: func(l layout) Set {
				return Set{Loaded: []Skill{globalSkill(l, "foo")}, Skipped: []Skipped{{filepath.Join(l.p, "foo"), MissingDescription}}}
			},
		},
		{
			name:  "folder without SKILL.md and top-level file ignored",
			files: map[string]string{"g/real": valid("real"), "g/nothing/README.md": "x", "g/./file.md": "x"},
			want:  func(l layout) Set { return Set{Loaded: []Skill{globalSkill(l, "real")}} },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newLayout(t)
			for key, content := range tc.files {
				layer, rel, _ := strings.Cut(key, "/")
				root := map[string]string{"g": l.g, "p": l.p}[layer]
				if strings.Contains(rel, "/") {
					writeFile(t, filepath.Join(root, rel), content)
				} else {
					writeFile(t, filepath.Join(root, rel, "SKILL.md"), content)
				}
			}
			check(t, l.load(t), tc.want(l))
		})
	}
}

func skipped(key string, reason Reason) func(l layout) Set {
	return func(l layout) Set {
		layer, rel, _ := strings.Cut(key, "/")
		root := map[string]string{"g": l.g, "p": l.p}[layer]
		return Set{Skipped: []Skipped{{filepath.Join(root, rel), reason}}}
	}
}

func TestLoadExactLimit(t *testing.T) {
	l := newLayout(t)
	content := valid("edge")
	writeFile(t, filepath.Join(l.g, "edge", "SKILL.md"), content)
	check(t, Load(l.home, l.project, nil, len(content)), Set{Loaded: []Skill{globalSkill(l, "edge")}})
	check(t, Load(l.home, l.project, nil, len(content)-1), Set{Skipped: []Skipped{{filepath.Join(l.g, "edge"), TooLarge}}})
}

func TestLoadSymlinks(t *testing.T) {
	l := newLayout(t)
	outside := filepath.Join(l.base, "outside")
	writeFile(t, filepath.Join(outside, "outdir", "SKILL.md"), valid("outdir"))
	writeFile(t, filepath.Join(outside, "file.md"), valid("outfile"))
	mkfifo(t, filepath.Join(outside, "fifodir", "SKILL.md"))
	mkfifo(t, filepath.Join(outside, "fifo"))
	mkdir(t, filepath.Join(outside, "dir"))

	writeFile(t, filepath.Join(l.g, "vault", "inner", "SKILL.md"), valid("linked"))
	symlink(t, filepath.Join("vault", "inner"), filepath.Join(l.g, "linked"))
	writeFile(t, filepath.Join(l.g, "vault", "filelink.md"), valid("filelink"))
	symlink(t, filepath.Join("..", "vault", "filelink.md"), filepath.Join(l.g, "filelink", "SKILL.md"))
	writeFile(t, filepath.Join(l.g, "vault", "absinner", "SKILL.md"), valid("abslinked"))
	symlink(t, filepath.Join(l.g, "vault", "absinner"), filepath.Join(l.g, "abslinked"))
	writeFile(t, filepath.Join(l.g, "vault", "absfilelink.md"), valid("absfilelink"))
	symlink(t, filepath.Join(l.g, "vault", "absfilelink.md"), filepath.Join(l.g, "absfilelink", "SKILL.md"))
	symlink(t, filepath.Join(outside, "outdir"), filepath.Join(l.g, "vault", "out"))
	symlink(t, filepath.Join(l.g, "vault", "out"), filepath.Join(l.g, "absvia"))

	symlink(t, filepath.Join(outside, "outdir"), filepath.Join(l.g, "outdir"))
	symlink(t, filepath.Join("..", "..", "..", "..", "outside", "outdir"), filepath.Join(l.g, "reloutdir"))
	symlink(t, filepath.Join(outside, "fifodir"), filepath.Join(l.g, "fifodir"))
	symlink(t, filepath.Join(outside, "file.md"), filepath.Join(l.g, "outfile", "SKILL.md"))
	symlink(t, filepath.Join(outside, "fifo"), filepath.Join(l.g, "fifofile", "SKILL.md"))
	symlink(t, filepath.Join(outside, "dir"), filepath.Join(l.g, "dirfile", "SKILL.md"))

	reads := countReads(t)
	check(t, l.load(t), Set{
		Loaded: []Skill{globalSkill(l, "absfilelink"), globalSkill(l, "abslinked"), globalSkill(l, "filelink"), globalSkill(l, "linked")},
		Skipped: []Skipped{
			{filepath.Join(l.g, "absvia"), OutsideFolder},
			{filepath.Join(l.g, "dirfile"), OutsideFolder},
			{filepath.Join(l.g, "fifodir"), OutsideFolder},
			{filepath.Join(l.g, "fifofile"), OutsideFolder},
			{filepath.Join(l.g, "outdir"), OutsideFolder},
			{filepath.Join(l.g, "outfile"), OutsideFolder},
			{filepath.Join(l.g, "reloutdir"), OutsideFolder},
		},
	})
	if *reads != 4 {
		t.Fatalf("reads = %d, want 4 (only the in-root skills)", *reads)
	}
}

func TestLoadSwapAfterEnumeration(t *testing.T) {
	tests := []struct {
		name string
		swap func(t *testing.T, l layout, outside string)
	}{
		{
			name: "skill folder replaced by escaping symlink",
			swap: func(t *testing.T, l layout, outside string) {
				if err := os.Rename(filepath.Join(l.g, "swap"), filepath.Join(l.base, "moved")); err != nil {
					t.Fatal(err)
				}
				symlink(t, outside, filepath.Join(l.g, "swap"))
			},
		},
		{
			name: "SKILL.md replaced by escaping symlink",
			swap: func(t *testing.T, l layout, outside string) {
				path := filepath.Join(l.g, "swap", "SKILL.md")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				symlink(t, filepath.Join(outside, "SKILL.md"), path)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newLayout(t)
			outside := filepath.Join(l.base, "outside")
			writeFile(t, filepath.Join(outside, "SKILL.md"), valid("swap"))
			writeFile(t, filepath.Join(l.g, "swap", "SKILL.md"), "no front matter")
			real := openFile
			stub(t, &openFile, func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
				tc.swap(t, l, outside)
				return real(r, name, flag, perm)
			})
			check(t, l.load(t), Set{Skipped: []Skipped{{filepath.Join(l.g, "swap"), OutsideFolder}}})
		})
	}
}

func TestLoadRootSwapAfterAcquisitionReadsOpenedRoot(t *testing.T) {
	l := newLayout(t)
	writeFile(t, filepath.Join(l.p, "kept", "SKILL.md"), valid("kept"))
	outside := filepath.Join(l.base, "outside")
	writeFile(t, filepath.Join(outside, "kept", "SKILL.md"), "no front matter")
	real := openFile
	stub(t, &openFile, func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
		if err := os.Rename(l.p, filepath.Join(l.base, "moved")); err != nil {
			t.Fatal(err)
		}
		symlink(t, outside, l.p)
		return real(r, name, flag, perm)
	})
	check(t, l.load(t), Set{Loaded: []Skill{projectSkill(l, "kept")}})
}

func TestLoadNonRegularTargets(t *testing.T) {
	l := newLayout(t)
	mkfifo(t, filepath.Join(l.g, "fifo", "SKILL.md"))
	mkfifo(t, filepath.Join(l.g, "vault", "pipe"))
	symlink(t, filepath.Join("..", "vault", "pipe"), filepath.Join(l.g, "linkfifo", "SKILL.md"))
	mkdir(t, filepath.Join(l.g, "dir", "SKILL.md"))
	reads := countReads(t)
	check(t, l.load(t), Set{Skipped: []Skipped{
		{filepath.Join(l.g, "dir"), Unreadable},
		{filepath.Join(l.g, "fifo"), Unreadable},
		{filepath.Join(l.g, "linkfifo"), Unreadable},
	}})
	if *reads != 0 {
		t.Fatalf("reads = %d, want non-regular targets rejected before reading", *reads)
	}
}

func TestLoadFIFOSwappedInBeforeOpen(t *testing.T) {
	l := newLayout(t)
	path := filepath.Join(l.g, "race", "SKILL.md")
	writeFile(t, path, valid("race"))
	real := openFile
	stub(t, &openFile, func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		mkfifo(t, path)
		return real(r, name, flag, perm)
	})
	check(t, l.load(t), Set{Skipped: []Skipped{{filepath.Join(l.g, "race"), Unreadable}}})
}

func TestLoadBoundedRead(t *testing.T) {
	tests := []struct {
		name   string
		change func(path string) error
	}{
		{"grows after stat", func(path string) error {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			_, err = f.WriteString("more")
			return errors.Join(err, f.Close())
		}},
		{"shrinks after stat", func(path string) error { return os.Truncate(path, 3) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newLayout(t)
			path := filepath.Join(l.g, "moving", "SKILL.md")
			writeFile(t, path, valid("moving"))
			stub(t, &readLimited, func(f *os.File, limit int64) ([]byte, error) {
				if err := tc.change(path); err != nil {
					t.Fatal(err)
				}
				return io.ReadAll(io.LimitReader(f, limit))
			})
			check(t, l.load(t), Set{Skipped: []Skipped{{filepath.Join(l.g, "moving"), Unreadable}}})
		})
	}
}

func TestLoadTooLargeNotRead(t *testing.T) {
	l := newLayout(t)
	writeFile(t, filepath.Join(l.g, "big", "SKILL.md"), valid("big")+strings.Repeat("x", testMax))
	reads := countReads(t)
	check(t, l.load(t), Set{Skipped: []Skipped{{filepath.Join(l.g, "big"), TooLarge}}})
	if *reads != 0 {
		t.Fatalf("reads = %d, want over-limit file rejected before reading", *reads)
	}
}

func TestLoadRoots(t *testing.T) {
	t.Run("missing roots", func(t *testing.T) {
		l := newLayout(t)
		check(t, l.load(t), Set{})
	})
	t.Run("root not a directory", func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, l.p, "x")
		check(t, l.load(t), Set{Skipped: []Skipped{{l.p, Unreadable}}})
	})
	t.Run("project root equals home", func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, filepath.Join(l.g, "one", "SKILL.md"), valid("one"))
		check(t, Load(l.home, l.home, nil, testMax), Set{Loaded: []Skill{globalSkill(l, "one")}})
	})
	t.Run("project root links to global root", func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, filepath.Join(l.g, "one", "SKILL.md"), valid("one"))
		symlink(t, l.g, l.p)
		check(t, l.load(t), Set{Loaded: []Skill{globalSkill(l, "one")}})
	})
	t.Run("safe symlinked roots", func(t *testing.T) {
		l := newLayout(t)
		elsewhere := filepath.Join(l.base, "elsewhere")
		writeFile(t, filepath.Join(elsewhere, "g", "one", "SKILL.md"), valid("one"))
		writeFile(t, filepath.Join(elsewhere, "p", "two", "SKILL.md"), valid("two"))
		symlink(t, filepath.Join(elsewhere, "g"), l.g)
		symlink(t, filepath.Join(elsewhere, "p"), l.p)
		check(t, l.load(t), Set{Loaded: []Skill{globalSkill(l, "one"), projectSkill(l, "two")}})
	})
	t.Run("symlinked state directory", func(t *testing.T) {
		l := newLayout(t)
		state := filepath.Join(l.base, "state")
		writeFile(t, filepath.Join(state, "skills", "one", "SKILL.md"), valid("one"))
		symlink(t, state, filepath.Join(l.home, ".codemeld"))
		check(t, l.load(t), Set{Loaded: []Skill{globalSkill(l, "one")}})
	})

	redirects := []struct {
		name   string
		global bool
		target func(l layout) string
	}{
		{"project to home", false, func(l layout) string { return l.home }},
		{"project to state", false, func(l layout) string { return filepath.Join(l.home, ".codemeld") }},
		{"project to sessions", false, func(l layout) string { return filepath.Join(l.home, ".codemeld", "sessions") }},
		{"project to filesystem root", false, func(l layout) string { return "/" }},
		{"global to sessions", true, func(l layout) string { return filepath.Join(l.home, ".codemeld", "sessions") }},
	}
	for _, tc := range redirects {
		t.Run("redirect "+tc.name, func(t *testing.T) {
			l := newLayout(t)
			for _, dir := range []string{l.home, filepath.Join(l.home, ".codemeld"), filepath.Join(l.home, ".codemeld", "sessions")} {
				writeFile(t, filepath.Join(dir, "evil", "SKILL.md"), valid("evil"))
			}
			root := l.p
			if tc.global {
				root = l.g
				mkdir(t, filepath.Dir(root))
			}
			symlink(t, tc.target(l), root)
			reads := countReads(t)
			check(t, l.load(t), Set{Skipped: []Skipped{{root, OutsideFolder}}})
			if *reads != 0 {
				t.Fatalf("reads = %d, want none", *reads)
			}
		})
	}
}

func TestLoadRootReplacedBeforeAcquisition(t *testing.T) {
	targets := []struct {
		name   string
		target func(l layout) string
	}{
		{"home", func(l layout) string { return l.home }},
		{"state", func(l layout) string { return filepath.Join(l.home, ".codemeld") }},
		{"sessions", func(l layout) string { return filepath.Join(l.home, ".codemeld", "sessions") }},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			l := newLayout(t)
			writeFile(t, filepath.Join(l.p, "fine", "SKILL.md"), valid("fine"))
			target := tc.target(l)
			writeFile(t, filepath.Join(target, "evil", "SKILL.md"), valid("evil"))
			real := openRoot
			stub(t, &openRoot, func(name string) (*os.Root, error) {
				if name == l.p {
					if err := os.Rename(l.p, filepath.Join(l.base, "moved")); err != nil {
						t.Fatal(err)
					}
					symlink(t, target, l.p)
				}
				return real(name)
			})
			reads := countReads(t)
			check(t, l.load(t), Set{Skipped: []Skipped{{l.p, OutsideFolder}}})
			if *reads != 0 {
				t.Fatalf("reads = %d, want the replaced root refused before any read", *reads)
			}
		})
	}
}

func TestLoadSortOrder(t *testing.T) {
	t.Run("by name and basename with rejected root", func(t *testing.T) {
		l := newLayout(t)
		for _, name := range []string{"mike", "bravo", "yankee", "delta", "alpha"} {
			writeFile(t, filepath.Join(l.g, name, "SKILL.md"), valid(name))
		}
		writeFile(t, filepath.Join(l.g, "zeta", "SKILL.md"), valid("Zeta"))
		writeFile(t, filepath.Join(l.g, "tango", "SKILL.md"), valid("other"))
		symlink(t, l.home, l.p)
		check(t, l.load(t), Set{
			Loaded: []Skill{globalSkill(l, "alpha"), globalSkill(l, "bravo"), globalSkill(l, "delta"), globalSkill(l, "mike"), globalSkill(l, "yankee")},
			Skipped: []Skipped{
				{l.p, OutsideFolder},
				{filepath.Join(l.g, "tango"), NameMismatch},
				{filepath.Join(l.g, "zeta"), BadName},
			},
		})
	})
	t.Run("same basename by path", func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, filepath.Join(l.p, "x", "SKILL.md"), valid("X"))
		writeFile(t, filepath.Join(l.p, "a", "SKILL.md"), valid("A"))
		writeFile(t, filepath.Join(l.g, "x", "SKILL.md"), valid("y"))
		writeFile(t, filepath.Join(l.g, "b", "SKILL.md"), valid("B"))
		check(t, l.load(t), Set{Skipped: []Skipped{
			{filepath.Join(l.p, "a"), BadName},
			{filepath.Join(l.g, "b"), BadName},
			{filepath.Join(l.home, ".codemeld", "skills", "x"), NameMismatch},
			{filepath.Join(l.project, ".codemeld", "skills", "x"), BadName},
		}})
	})
}

func TestRootAllowed(t *testing.T) {
	home := "/nonexistent-skills-home/u"
	tests := []struct {
		root string
		want bool
	}{
		{"/nonexistent-skills-home/u", false},
		{"/nonexistent-skills-home", false},
		{"/", false},
		{"/nonexistent-skills-home/u/.codemeld", false},
		{"/nonexistent-skills-home/u/.codemeld/sessions", false},
		{"/nonexistent-skills-home/u/.codemeld/global", false},
		{"/nonexistent-skills-home/u/.codemeld/skillsx", false},
		{"/nonexistent-skills-home/u/.codemeld/skills", true},
		{"/nonexistent-skills-home/u/.codemeld/skills/nested", true},
		{"/nonexistent-skills-home/u/project/.codemeld/skills", true},
		{"/nonexistent-skills-home/u/.codemeldx", true},
		{"/elsewhere/skills", true},
	}
	for _, tc := range tests {
		if got := RootAllowed(home, tc.root); got != tc.want {
			t.Errorf("RootAllowed(%q, %q) = %v, want %v", home, tc.root, got, tc.want)
		}
	}

	base := t.TempDir()
	real := filepath.Join(base, "real")
	mkdir(t, filepath.Join(real, ".codemeld", "sessions"))
	mkdir(t, filepath.Join(real, ".codemeld", "skills"))
	link := filepath.Join(base, "link")
	symlink(t, real, link)
	linked := []struct {
		root string
		want bool
	}{
		{real, false},
		{filepath.Join(real, ".codemeld"), false},
		{filepath.Join(real, ".codemeld", "sessions"), false},
		{filepath.Join(real, ".codemeld", "skills"), true},
	}
	for _, tc := range linked {
		if got := RootAllowed(link, tc.root); got != tc.want {
			t.Errorf("RootAllowed(symlinked home, %q) = %v, want %v", tc.root, got, tc.want)
		}
	}
}
