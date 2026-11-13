package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/permissions"
)

type hostileControl struct{ name, value string }

func hostileControls() []hostileControl {
	var values []hostileControl
	for r := rune(0); r <= 0x9f; r++ {
		if r >= 0x20 && r < 0x7f {
			continue
		}
		values = append(values, hostileControl{fmt.Sprintf("U+%04X", r), string(r)})
	}
	return append(values,
		hostileControl{"CSI clear 7-bit", "\x1b[2J"},
		hostileControl{"CSI clear 8-bit", "\u009b2J"},
		hostileControl{"OSC title 7-bit", "\x1b]0;pwn\x07"},
		hostileControl{"OSC title 8-bit", "\u009d0;pwn\x07"},
		hostileControl{"DCS 7-bit", "\x1bPq#0\x1b\\"},
		hostileControl{"DCS 8-bit", "\u0090q#0\u009c"},
	)
}

func escapedControls(s string, keepLayout bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case keepLayout && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02X`, r)
		case r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func marked(tag, v string) string { return tag + "<" + v + ">" + tag }

var requestLines = regexp.MustCompile(`(  Request: [^\n]*, )(\d+) lines,`)

func escapedLike(benign, v string, keepLayout bool, payload string) string {
	if added := strings.Count(v, "\n") * strings.Count(payload, "<"+v+">"); keepLayout && added > 0 {
		benign = requestLines.ReplaceAllStringFunc(benign, func(line string) string {
			m := requestLines.FindStringSubmatch(line)
			n, _ := strconv.Atoi(m[2])
			return m[1] + strconv.Itoa(n+added) + " lines,"
		})
	}
	return strings.ReplaceAll(benign, "<"+withoutControls(v)+">", "<"+escapedControls(v, keepLayout)+">")
}

type hostileInput struct {
	req  permissions.MatchRequest
	disp dispatch.PromptDisplay
	d    terminalDisclosure
	esc  permissions.ScopeEscalation
	want []string
}

func markerDisclosure(root string) terminalDisclosure {
	return terminalDisclosure{
		projectRoot:             root,
		launchDir:               root,
		boundary:                "launch-dir-only",
		folderSettingsPath:      root + "/.codemeld/settings.yaml",
		wouldCreateSettingsFile: true,
	}
}

type hostileField struct {
	kind, field string
	multiline   bool
	build       func(v string) hostileInput
}

func toolBase(tool, action string) hostileInput {
	return hostileInput{
		req:  permissions.MatchRequest{Kind: matchKindTool, Subject: tool, PathScope: "/proj/sub"},
		disp: dispatch.PromptDisplay{Action: action, Subject: "notes.md", RequestedTarget: "notes.md", GrantStoredSubject: permissions.CapabilityWriteTree},
		d:    markerDisclosure("/proj"),
	}
}

func literalBase() hostileInput {
	const command = "true && echo done"
	return hostileInput{
		req:  permissions.MatchRequest{Kind: matchKindLiteral, Subject: command, PathScope: "/proj/sub"},
		disp: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: command, WholeCommand: true},
		d:    markerDisclosure("/proj"),
	}
}

func commonHostileFields(kind string, base func() hostileInput) []hostileField {
	single := func(field string, set func(in *hostileInput, v string)) hostileField {
		return hostileField{kind: kind, field: field, build: func(v string) hostileInput {
			in := base()
			set(&in, v)
			return in
		}}
	}
	return []hostileField{
		single("PathScope", func(in *hostileInput, v string) {
			in.req.PathScope = "/proj/" + marked("PS", v)
			in.want = []string{"  path: " + escapedControls(in.req.PathScope, false) + "\n"}
		}),
		single("ProjectRoot", func(in *hostileInput, v string) {
			root := "/" + marked("PR", v)
			in.d = markerDisclosure(root)
			in.d.folderSettingsPath = "/proj/.codemeld/settings.yaml"
			in.req.PathScope = root + "/sub"
			in.want = []string{
				"  project root: " + escapedControls(root, false) + "\n",
				"created " + escapedControls(root+"/.codemeld/settings.yaml", false) + " — ",
			}
		}),
		single("FolderSettingsPath", func(in *hostileInput, v string) {
			in.d.folderSettingsPath = "/proj/" + marked("FS", v) + "/settings.yaml"
			in.want = []string{"permanently in " + escapedControls(in.d.folderSettingsPath, false) + "\n"}
		}),
		single("Note", func(in *hostileInput, v string) {
			in.esc.Note = marked("NO", v)
			in.want = []string{"  " + escapedControls(in.esc.Note, false) + "\n"}
		}),
		single("NarrowerScope", func(in *hostileInput, v string) {
			in.esc.NarrowerScope = "/proj/sub/" + marked("NS", v)
			in.want = []string{"PARENT of " + escapedControls(in.esc.NarrowerScope, false) + "\n"}
		}),
	}
}

func hostileFields() []hostileField {
	var fields []hostileField
	add := func(kind, field string, multiline bool, base func() hostileInput, set func(in *hostileInput, v string)) {
		fields = append(fields, hostileField{kind: kind, field: field, multiline: multiline, build: func(v string) hostileInput {
			in := base()
			set(&in, v)
			return in
		}})
	}

	add("literal", "Subject", true, literalBase, func(in *hostileInput, v string) {
		in.disp.Subject = "true && echo '" + marked("SU", v) + "'"
		in.req.Subject = in.disp.Subject
		in.want = []string{"  Run command: true && echo '" + escapedControls(marked("SU", v), true) + "'\n"}
	})
	fields = append(fields, commonHostileFields("literal", literalBase)...)

	for _, tool := range []struct{ name, action string }{
		{"create", dispatch.ActionCreateFile},
		{"edit", dispatch.ActionEditFile},
		{"mkdir", dispatch.ActionCreateDirectory},
	} {
		base := func() hostileInput { return toolBase(tool.name, tool.action) }
		add(tool.name, "Subject", true, base, func(in *hostileInput, v string) {
			in.disp.Subject = marked("SU", v)
			in.want = []string{"  " + tool.action + ": " + escapedControls(in.disp.Subject, true) + "\n"}
		})
		if tool.name != "mkdir" {
			add(tool.name, "Body", true, base, func(in *hostileInput, v string) {
				in.disp.Body = "-old\n+" + marked("BO", v)
				in.want = []string{"\n" + escapedControls(in.disp.Body, true) + "\n"}
			})
		}
		add(tool.name, "RequestedTarget", false, base, func(in *hostileInput, v string) {
			in.disp.RequestedTarget = marked("RT", v)
			in.want = []string{"  Requested target: " + escapedControls(in.disp.RequestedTarget, false) + "\n"}
		})
		fields = append(fields, commonHostileFields(tool.name, base)...)
	}

	hostBase := func() hostileInput {
		return hostileInput{
			req:  hostRequest("web_fetch", "docs.example.com"),
			disp: dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "web_fetch", HostRequest: "https://docs.example.com/guide"},
			d:    markerDisclosure("/proj"),
		}
	}
	add("host", "Subject", false, hostBase, func(in *hostileInput, v string) {
		in.req.Subject = marked("HT", v)
		in.want = []string{"  tool: " + escapedControls(in.req.Subject, false) + "\n"}
	})
	add("host", "HostRequest", true, hostBase, func(in *hostileInput, v string) {
		in.disp.HostRequest = "https://docs.example.com/" + marked("HR", v)
		in.want = []string{"  request: " + escapedControls(in.disp.HostRequest, true) + "\n"}
	})
	add("host", "Host", false, hostBase, func(in *hostileInput, v string) {
		in.req.Host = marked("HO", v) + ".example.com"
		in.want = []string{
			"  host: " + escapedControls(in.req.Host, false) + "\n",
			"  Requested target: " + escapedControls(in.req.Host, false) + "\n",
		}
	})
	return fields
}

func renderHostileInput(t *testing.T, in hostileInput, input string) string {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	p.notifyTTY = false
	p.disclosure = in.d
	if _, err := p.build(in.req, in.disp)(context.Background(), in.esc); err != nil {
		t.Fatalf("prompt: %v", err)
	}
	return out.String()
}

func TestTerminalPrompter_HostileControlsInEveryPreviewField(t *testing.T) {
	for _, f := range hostileFields() {
		for _, hv := range hostileControls() {
			t.Run(f.kind+"/"+f.field+"/"+hv.name, func(t *testing.T) {
				hostile := f.build(hv.value)
				got := renderHostileInput(t, hostile, "3\n")
				if strings.Contains(got, "this grant stores a command subject") {
					t.Fatalf("a %s request opened the direct-command chooser:\n%s", f.kind, got)
				}
				allowed := "\n"
				if f.multiline {
					allowed = "\n\t"
				}
				if raw := rawControls(got, allowed); len(raw) > 0 {
					t.Fatalf("output emitted raw controls %q:\n%q", raw, got)
				}
				benign := renderHostileInput(t, f.build(withoutControls(hv.value)), "3\n")
				if !f.multiline {
					if rows, want := strings.Count(got, "\n"), strings.Count(benign, "\n"); rows != want {
						t.Fatalf("output has %d rows, want the benign %d:\n%s", rows, want, got)
					}
				}
				payload := hostile.disp.Body + hostile.disp.HostRequest
				if f.kind == "literal" {
					payload = hostile.disp.Subject
				}
				if want := escapedLike(benign, hv.value, f.multiline, payload); got != want {
					t.Fatalf("output is not the benign output with the value escaped:\ngot:\n%s\nwant:\n%s", got, want)
				}
				for _, want := range hostile.want {
					if !strings.Contains(got, want) {
						t.Fatalf("output missing %q:\n%s", want, got)
					}
				}
			})
		}
	}
}

type directHostileCase struct {
	field   string
	command string
	scope   string
	d       terminalDisclosure
	esc     permissions.ScopeEscalation
	want    map[string][]string
}

func newDirectHostileCase(field, v string) directHostileCase {
	c := directHostileCase{field: field, command: "grep sub needle", scope: "/proj/sub", d: markerDisclosure("/proj"), want: map[string][]string{}}
	switch field {
	case "command":
		c.command = "'" + marked("PG", v) + "' sub '" + marked("AR", v) + "'"
		program := escapedControls(marked("PG", v), false)
		pg, ar := "'"+program+"'", "'"+escapedControls(marked("AR", v), false)+"'"
		c.want["preview"] = []string{"  Run command: '" + escapedControls(marked("PG", v), true) + "' sub '" + escapedControls(marked("AR", v), true) + "'\n"}
		c.want["chooser"] = []string{"  canonical command: " + pg + " sub " + ar + "\n"}
		c.want["rows"] = []string{
			"  [1] exact: " + pg + " sub " + ar + " — only this exact command",
			"  [2] prefix: " + pg + " sub " + ar + " :* — fixed: " + pg + " sub " + ar + "; any later arguments may vary",
			"  [3] prefix: " + pg + " sub :* — fixed: " + pg + " sub; any later arguments may vary",
			"  [4] program (advanced): " + pg + " :* — ANY invocation of " + program + " (widest)",
		}
		c.want["confirm"] = []string{"  effective grant: " + pg + " :* (direct command)\n"}
	case "PathScope":
		c.scope = "/proj/" + marked("PS", v)
		scope := escapedControls(c.scope, false)
		c.want["preview"] = []string{"  path: " + scope + "\n"}
		c.want["chooser"] = []string{"  run folder: " + scope + "\n"}
		c.want["confirm"] = []string{"  applies to: " + scope + " and its descendants\n"}
	case "ProjectRoot":
		root := "/" + marked("PR", v)
		c.d = markerDisclosure(root)
		c.d.folderSettingsPath = "/proj/.codemeld/settings.yaml"
		c.scope = root + "/sub"
		c.want["preview"] = []string{"  project root: " + escapedControls(root, false) + "\n"}
		c.want["chooser"] = []string{"  project root: " + escapedControls(root, false) + "\n"}
		c.want["persisted"] = []string{"created " + escapedControls(root+"/.codemeld/settings.yaml", false) + " — "}
	case "FolderSettingsPath":
		c.d.folderSettingsPath = "/proj/" + marked("FS", v) + "/settings.yaml"
		c.want["preview"] = []string{"permanently in " + escapedControls(c.d.folderSettingsPath, false) + "\n"}
		c.want["persisted"] = []string{"  saved to: " + escapedControls(c.d.folderSettingsPath, false) + "\n"}
	case "Note":
		c.esc.Note = marked("NO", v)
		c.want["preview"] = []string{"  " + escapedControls(c.esc.Note, false) + "\n"}
	case "NarrowerScope":
		c.esc.NarrowerScope = "/proj/sub/" + marked("NS", v)
		c.want["preview"] = []string{"this asks for the PARENT of " + escapedControls(c.esc.NarrowerScope, false) + "\n"}
	}
	return c
}

func directChoiceRow(t *testing.T, req permissions.MatchRequest, home string, kind permissions.DirectScopeKind) (int, permissions.DirectScopeChoice) {
	t.Helper()
	model, ok := permissions.NewDirectScopeModel(req.SubjectTokens, home)
	if !ok {
		t.Fatalf("no direct scope model for %q", req.SubjectTokens)
	}
	for i, c := range headlessScopeChoices(model) {
		if c.Kind == kind {
			return i, c
		}
	}
	t.Fatalf("tokens %q offer no scope choice of kind %v", req.SubjectTokens, kind)
	return 0, permissions.DirectScopeChoice{}
}

func assertDirectSections(t *testing.T, s, benign promptSections, v, payload, previewAllowed string, want map[string][]string, persisted, confirmed bool) {
	t.Helper()
	sections := []struct {
		name          string
		got, baseline string
		allowed       string
	}{
		{"preview", s.preview, benign.preview, previewAllowed},
		{"chooser", s.chooser, benign.chooser, "\n"},
		{"confirm", s.confirm, benign.confirm, "\n"},
	}
	for _, sec := range sections {
		if raw := rawControls(sec.got, sec.allowed); len(raw) > 0 {
			t.Fatalf("%s emitted raw controls %q:\n%q", sec.name, raw, sec.got)
		}
		if sec.allowed == "\n" {
			if rows, wantRows := strings.Count(sec.got, "\n"), strings.Count(sec.baseline, "\n"); rows != wantRows {
				t.Fatalf("%s has %d rows, want the benign %d:\n%s", sec.name, rows, wantRows, sec.got)
			}
		}
		if want := escapedLike(sec.baseline, v, sec.allowed != "\n", payload); sec.got != want {
			t.Fatalf("%s is not the benign %s with the value escaped:\ngot:\n%s\nwant:\n%s", sec.name, sec.name, sec.got, want)
		}
	}
	if (s.confirm != "") != confirmed {
		t.Fatalf("confirmation shown = %v, want %v:\n%s", s.confirm != "", confirmed, s.confirm)
	}
	check := func(section, text string) {
		for _, w := range want[section] {
			if !strings.Contains(text, w) {
				t.Fatalf("%s missing %q:\n%s", section, w, text)
			}
		}
	}
	check("preview", s.preview)
	check("chooser", s.chooser)
	rows := strings.Split(s.chooser, "\n")
	for _, w := range want["rows"] {
		if !slices.ContainsFunc(rows, func(row string) bool { return row == w || row == w+" [recommended]" }) {
			t.Fatalf("chooser has no row %q:\n%s", w, s.chooser)
		}
	}
	if confirmed {
		check("confirm", s.confirm)
	}
	if persisted {
		check("persisted", s.chooser)
		if confirmed {
			check("persisted", s.confirm)
		}
	}
}

func renderEscalatedDirectSections(t *testing.T, input string, req permissions.MatchRequest, disp dispatch.PromptDisplay, d terminalDisclosure, esc permissions.ScopeEscalation) (promptSections, permissions.PromptOutcome) {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	p.notifyTTY = false
	p.disclosure = d
	outcome, err := p.build(req, disp)(context.Background(), esc)
	if err != nil {
		t.Fatalf("direct prompt: %v", err)
	}
	got := out.String()
	chooserAt := strings.Index(got, "\ncodemeld: this grant stores a command subject")
	if chooserAt < 0 {
		t.Fatalf("no scope chooser:\n%q", got)
	}
	s := promptSections{preview: got[:chooserAt], chooser: got[chooserAt:]}
	const choosePrompt = "codemeld: choose 1-"
	promptAt := strings.Index(s.chooser, choosePrompt) + len(choosePrompt)
	confirmAt := promptAt + strings.Index(s.chooser[promptAt:], ": ") + len(": ")
	s.chooser, s.confirm = s.chooser[:confirmAt], s.chooser[confirmAt:]
	return s, outcome
}

func TestTerminalPrompter_HostileControlsInDirectCommandScopes(t *testing.T) {
	lifetimes := []struct {
		name      string
		answer    string
		persisted bool
	}{{"session", "3\n", false}, {"persisted", "4\n", true}}
	choices := []struct {
		name string
		kind permissions.DirectScopeKind
	}{{"exact", permissions.DirectScopeExact}, {"prefix", permissions.DirectScopePrefix}, {"program", permissions.DirectScopeProgram}}

	for _, field := range []string{"command", "PathScope", "ProjectRoot", "FolderSettingsPath", "Note", "NarrowerScope"} {
		for _, hv := range hostileControls() {
			for _, lt := range lifetimes {
				for _, choice := range choices {
					t.Run(field+"/"+hv.name+"/"+lt.name+"/"+choice.name, func(t *testing.T) {
						c := newDirectHostileCase(field, hv.value)
						b := newDirectHostileCase(field, withoutControls(hv.value))
						req, disp := splitDirectRequest(t, c.command, c.scope)
						benignReq, benignDisp := splitDirectRequest(t, b.command, b.scope)
						row, selected := directChoiceRow(t, req, "", choice.kind)
						benignRow, _ := directChoiceRow(t, benignReq, "", choice.kind)
						if row != benignRow {
							t.Fatalf("%s choice is row %d, benign row %d", choice.name, row, benignRow)
						}
						input := fmt.Sprintf("%s%d\n", lt.answer, row+1)
						confirmed := choice.kind == permissions.DirectScopeProgram
						if confirmed {
							input += "1\n"
						}
						s, outcome := renderEscalatedDirectSections(t, input, req, disp, c.d, c.esc)
						benign, _ := renderEscalatedDirectSections(t, input, benignReq, benignDisp, b.d, b.esc)

						previewAllowed := "\n"
						if field == "command" {
							previewAllowed = "\n\t"
						}
						assertDirectSections(t, s, benign, hv.value, disp.Subject, previewAllowed, c.want, lt.persisted, confirmed)
						if outcome.StoredSubject != selected.Subject {
							t.Fatalf("stored subject = %q, want the model subject %q", outcome.StoredSubject, selected.Subject)
						}
						if field == "command" && !strings.Contains(outcome.StoredSubject, marked("PG", hv.value)) {
							t.Fatalf("stored subject %q lost the unescaped program token %q", outcome.StoredSubject, marked("PG", hv.value))
						}
					})
				}
			}
		}
	}
}

func hostileBoundaryRequest(t *testing.T, dirName string) (permissions.MatchRequest, dispatch.PromptDisplay, string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	home := filepath.Join(root, "home", "user")
	widest := filepath.Join(root, dirName)
	entry := filepath.Join(widest, "run", "id")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}
	if err := os.WriteFile(entry, nil, 0o644); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	req, disp := splitDirectRequest(t, "chmod +x '"+entry+"'", "/proj/sub")
	return req, disp, home, widest
}

func TestTerminalPrompter_HostileControlsInThePathBoundary(t *testing.T) {
	for _, hv := range hostileControls() {
		for _, lt := range []struct {
			name      string
			answer    string
			persisted bool
		}{{"session", "3\n", false}, {"persisted", "4\n", true}} {
			t.Run(hv.name+"/"+lt.name, func(t *testing.T) {
				if strings.ContainsRune(hv.value, 0) {
					t.Skip("unrepresentable: U+0000 cannot occur in a filename, so no real boundary can carry it")
				}
				dirName := marked("BD", hv.value)
				req, disp, home, widest := hostileBoundaryRequest(t, dirName)
				benignReq, benignDisp, benignHome, benignWidest := hostileBoundaryRequest(t, withoutControls(dirName))
				row, selected := directChoiceRow(t, req, home, permissions.DirectScopePath)
				if selected.Boundaries[selected.Boundary] != widest {
					t.Fatalf("offered boundary = %q, want the hostile widest boundary %q", selected.Boundaries[selected.Boundary], widest)
				}
				input := fmt.Sprintf("%s%d\n", lt.answer, row+1)
				s, outcome := renderDirectSections(t, input, home, req, disp, markerDisclosure("/proj"))
				benign, _ := renderDirectSections(t, input, benignHome, benignReq, benignDisp, markerDisclosure("/proj"))
				roots := strings.NewReplacer(filepath.Dir(benignWidest), filepath.Dir(widest))
				benign = promptSections{roots.Replace(benign.preview), roots.Replace(benign.chooser), roots.Replace(benign.confirm)}

				boundary := escapedControls(widest, false)
				want := map[string][]string{"chooser": {
					" against any path resolving under " + boundary + ", checked when permission is decided",
					"  The path choice is fixed at " + boundary + ", the widest boundary",
				}}
				assertDirectSections(t, s, benign, hv.value, disp.Subject, "\n\t", want, lt.persisted, false)
				wantSubject, err := permissions.EncodeDirectUnderSubject(req.SubjectTokens, 2, widest, false)
				if err != nil {
					t.Fatalf("EncodeDirectUnderSubject: %v", err)
				}
				if outcome.StoredSubject != wantSubject {
					t.Fatalf("stored subject = %q, want the unescaped widest-boundary grant %q", outcome.StoredSubject, wantSubject)
				}
			})
		}
	}
}
