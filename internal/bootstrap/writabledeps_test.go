package bootstrap

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
)

func readSettingsMap(t *testing.T, project string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(project, ".codemeld", "settings.yaml"))
	if err != nil {
		t.Fatalf("read project settings: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse project settings: %v", err)
	}
	return raw
}

func writableList(t *testing.T, project string) []string {
	t.Helper()
	var out []string
	for _, item := range readSettingsMap(t, project)["writable_folders"].([]any) {
		out = append(out, item.(string))
	}
	return out
}

func TestWritableFolders_AddCreatesTheProjectFile(t *testing.T) {
	project, folder := declaredScopeDir(t), declaredScopeDir(t)
	w := newWritableFolders(declaredScopeDir(t), project, true)

	msg := w.add(folder)

	if !strings.Contains(msg, "added") {
		t.Fatalf("add message = %q, want a success message", msg)
	}
	if got := writableList(t, project); !slices.Equal(got, []string{folder}) {
		t.Fatalf("writable_folders = %v, want [%s]", got, folder)
	}
}

func TestWritableFolders_AddReachesTheAdmittedLiveReader(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t)
	writeProjectSettings(t, f.project, writableFoldersYAML())
	r := liveFoldersReader(t, f, []string{f.global, f.projectFile}, f.home)
	folder := declaredScopeDir(t)

	newWritableFolders(f.home, f.project, true).add(folder)

	requireLiveFolders(t, r, folder)
}

func TestWritableFolders_NewNonAdmittedLayerGrantsNothingAndNeedsRestart(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t)
	cache, err := config.NewCache(map[string]any{}, f.project, []string{f.global}, f.home)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	r := newWritableFoldersReader(cache)
	w := newWritableFolders(f.home, f.project, true)
	folder := declaredScopeDir(t)

	w.add(folder)

	requireLiveFolders(t, r)
	view := w.deps(cache, &productionAuthorizer{}).List()
	if view.LayerAdmitted || len(view.Rows) != 1 || view.Rows[0].Entry != folder {
		t.Fatalf("view = %+v, want the one entry with the layer not admitted", view)
	}
}

func TestWritableFolders_RemoveDeletesOnlyThatEntry(t *testing.T) {
	project := declaredScopeDir(t)
	a, b, c := declaredScopeDir(t), declaredScopeDir(t), declaredScopeDir(t)
	writeProjectSettings(t, project, "agent:\n  max_concurrency: 7\n"+writableFoldersYAML(a, b, c))

	msg := newWritableFolders(declaredScopeDir(t), project, true).remove(b)

	if !strings.Contains(msg, "removed") {
		t.Fatalf("remove message = %q, want a success message", msg)
	}
	if got := writableList(t, project); !slices.Equal(got, []string{a, c}) {
		t.Fatalf("writable_folders = %v, want [%s %s]", got, a, c)
	}
	agent, _ := readSettingsMap(t, project)["agent"].(map[string]any)
	if agent["max_concurrency"] != uint64(7) {
		t.Fatalf("agent = %#v, want max_concurrency 7 kept", agent)
	}
}

func TestWritableFolders_AddValidatesTheEntry(t *testing.T) {
	home, project := declaredScopeDir(t), declaredScopeDir(t)
	if err := os.Mkdir(filepath.Join(home, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(declaredScopeDir(t), "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	existing := declaredScopeDir(t)
	cases := []struct {
		name, entry, want string
		written           []string
	}{
		{name: "relative", entry: "relative/dir", want: "must be an absolute path or start with ~/"},
		{name: "filesystem root", entry: "/", want: "the filesystem root cannot be a writable folder"},
		{name: "missing folder", entry: filepath.Join(existing, "missing"), want: "the folder does not exist"},
		{name: "inside .codemeld", entry: filepath.Join(project, ".codemeld", "inside"), want: "inside the project's protected codemeld folder"},
		{name: "a file", entry: file, want: "not a directory"},
		{name: "duplicate", entry: existing, want: "already in writable_folders", written: []string{existing}},
		{name: "home expansion", entry: "~/work", want: "~/work added", written: []string{existing, "~/work"}},
		{name: "home folder notice", entry: "~/", want: "may write under the home directory", written: []string{existing, "~/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeProjectSettings(t, project, writableFoldersYAML(existing))
			want := tc.written
			if want == nil {
				want = []string{existing}
			}

			msg := newWritableFolders(home, project, true).add(tc.entry)

			if !strings.Contains(msg, tc.want) {
				t.Fatalf("add(%q) = %q, want it to contain %q", tc.entry, msg, tc.want)
			}
			if got := writableList(t, project); !slices.Equal(got, want) {
				t.Fatalf("writable_folders = %v, want %v", got, want)
			}
		})
	}
}

func TestWritableFolders_NoApprovedRootRefusesEveryWrite(t *testing.T) {
	const refusal = "refused: project settings are not available for this launch (no approved project root); nothing written"
	folder := declaredScopeDir(t)
	cases := map[string]func(project string) writableFolders{
		"untrusted project": func(project string) writableFolders { return newWritableFolders(declaredScopeDir(t), project, false) },
		"no project root":   func(string) writableFolders { return newWritableFolders(declaredScopeDir(t), "", true) },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			project := declaredScopeDir(t)
			w := build(project)
			if got := w.add(folder); got != refusal {
				t.Fatalf("add = %q, want %q", got, refusal)
			}
			if got := w.remove(folder); got != refusal {
				t.Fatalf("remove = %q, want %q", got, refusal)
			}
			if _, err := os.Stat(filepath.Join(project, ".codemeld")); !os.IsNotExist(err) {
				t.Fatalf("stat .codemeld: %v, want nothing written", err)
			}
		})
	}
}

func TestWritableFolders_AddPersistsTheEntryAsTyped(t *testing.T) {
	project, base := declaredScopeDir(t), declaredScopeDir(t)
	plain, spaced := filepath.Join(base, "out"), filepath.Join(base, "out")+" "
	for _, dir := range []string{plain, spaced} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	add := newWritableFolders(declaredScopeDir(t), project, true).deps(nil, &productionAuthorizer{}).Add

	if msg := add(spaced); !strings.Contains(msg, "added") {
		t.Fatalf("add(%q) = %q, want a success message", spaced, msg)
	}
	if got := writableList(t, project); !slices.Equal(got, []string{spaced}) {
		t.Fatalf("writable_folders = %q, want exactly [%q]", got, spaced)
	}
}

func TestWritableFolders_ListReportsAFIFOSettingsFileUnreadable(t *testing.T) {
	project := declaredScopeDir(t)
	path := projectSettingsPath(project)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	type result struct {
		rows       int
		unreadable string
	}
	done := make(chan result, 1)
	go func() {
		rows, unreadable := newWritableFolders(declaredScopeDir(t), project, true).list()
		done <- result{len(rows), unreadable}
	}()

	select {
	case got := <-done:
		if got.unreadable == "" || got.rows != 0 {
			t.Fatalf("list = %d rows, unreadable %q; want no rows and an unreadable result", got.rows, got.unreadable)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("list blocked on a FIFO settings file")
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lstat lock file: %v, want none created", err)
	}
}

func writeLocalSettings(t *testing.T, project, content string) string {
	t.Helper()
	path := filepath.Join(project, ".codemeld", "settings.local.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireFileBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s =\n%q\nwant\n%q", path, got, want)
	}
}

func TestOutsideCommands_ListReadsOnlyTheLocalFile(t *testing.T) {
	project := declaredScopeDir(t)
	writeProjectSettings(t, project, "outside_sandbox_commands: [committed command]\n")
	writeLocalSettings(t, project, "outside_sandbox_commands: [mise run check]\n")

	rows, unreadable := newWritableFolders(declaredScopeDir(t), project, true).outsideCommands().list()

	if unreadable != "" || len(rows) != 1 || rows[0].Entry != "mise run check" || rows[0].Invalid != "" {
		t.Fatalf("list = %+v, %q; want only the valid local entry", rows, unreadable)
	}
}

func TestOutsideCommands_ListWithoutLocalFileIsEmpty(t *testing.T) {
	project := declaredScopeDir(t)
	writeProjectSettings(t, project, "outside_sandbox_commands: [committed command]\n")

	rows, unreadable := newWritableFolders(declaredScopeDir(t), project, true).outsideCommands().list()

	if unreadable != "" || len(rows) != 0 {
		t.Fatalf("list = %+v, %q; want an empty list", rows, unreadable)
	}
}

func TestOutsideCommands_ListMarksEntriesParseEntryRejects(t *testing.T) {
	project := declaredScopeDir(t)
	writeLocalSettings(t, project, "outside_sandbox_commands: [web_fetch, go vet ./...]\n")

	rows, unreadable := newWritableFolders(declaredScopeDir(t), project, true).outsideCommands().list()

	if unreadable != "" || len(rows) != 2 {
		t.Fatalf("list = %+v, %q; want two rows", rows, unreadable)
	}
	if !strings.Contains(rows[0].Invalid, "web_fetch") {
		t.Fatalf("rows[0].Invalid = %q, want the parse error for web_fetch", rows[0].Invalid)
	}
	if rows[1].Invalid != "" {
		t.Fatalf("rows[1].Invalid = %q, want a valid entry", rows[1].Invalid)
	}
}

func TestOutsideCommands_RemoveRewritesOnlyTheLocalFile(t *testing.T) {
	project := declaredScopeDir(t)
	const committed = "# shared\noutside_sandbox_commands: [mise run check]\n"
	writeProjectSettings(t, project, committed)
	local := writeLocalSettings(t, project, "# mine\noutside_sandbox_commands:\n- mise run check\n- go vet ./...\n")

	msg := newWritableFolders(declaredScopeDir(t), project, true).outsideCommands().remove("mise run check")

	if want := "mise run check removed from outside_sandbox_commands in " + local; msg != want {
		t.Fatalf("remove = %q, want %q", msg, want)
	}
	requireFileBytes(t, local, "# mine\noutside_sandbox_commands:\n- go vet ./...\n")
	requireFileBytes(t, filepath.Join(project, ".codemeld", "settings.yaml"), committed)
}

func TestOutsideCommands_RemoveAbsentEntryWritesNothing(t *testing.T) {
	t.Run("entry not in the local list", func(t *testing.T) {
		project := declaredScopeDir(t)
		const content = "outside_sandbox_commands: [go vet ./...]\n"
		local := writeLocalSettings(t, project, content)

		msg := newWritableFolders(declaredScopeDir(t), project, true).outsideCommands().remove("mise run check")

		if want := "mise run check is not in outside_sandbox_commands in " + local + "; nothing written"; msg != want {
			t.Fatalf("remove = %q, want %q", msg, want)
		}
		requireFileBytes(t, local, content)
	})
	t.Run("no local file", func(t *testing.T) {
		project := declaredScopeDir(t)

		msg := newWritableFolders(declaredScopeDir(t), project, true).outsideCommands().remove("mise run check")

		if !strings.HasSuffix(msg, "; nothing written") {
			t.Fatalf("remove = %q, want a nothing-written refusal", msg)
		}
		if _, err := os.Stat(filepath.Join(project, ".codemeld")); !os.IsNotExist(err) {
			t.Fatalf("stat .codemeld: %v, want nothing written", err)
		}
	})
}

func TestOutsideCommands_RemoveRefusesWithoutApprovedProject(t *testing.T) {
	const refusal = "refused: project settings are not available for this launch (no approved project root); nothing written"
	const content = "outside_sandbox_commands: [mise run check]\n"
	cases := map[string]func(project string) outsideCommands{
		"untrusted project": func(project string) outsideCommands {
			return newWritableFolders(declaredScopeDir(t), project, false).outsideCommands()
		},
		"no project root": func(string) outsideCommands {
			return newWritableFolders(declaredScopeDir(t), "", true).outsideCommands()
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			project := declaredScopeDir(t)
			local := writeLocalSettings(t, project, content)

			if got := build(project).remove("mise run check"); got != refusal {
				t.Fatalf("remove = %q, want %q", got, refusal)
			}
			requireFileBytes(t, local, content)
		})
	}
}
