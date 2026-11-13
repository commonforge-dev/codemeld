package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/permissions"
)

const (
	hostileScreenWidth  = 320
	hostileScreenHeight = 64
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

func isTerminalControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

func escapedControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
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

func markers(tags ...string) []string {
	var out []string
	for _, tag := range tags {
		out = append(out, tag+"<", ">"+tag)
	}
	return out
}

func exposedControls(screen tcell.SimulationScreen) []rune {
	cells, _, _ := screen.GetContents()
	var found []rune
	for _, c := range cells {
		for _, r := range c.Runes {
			if isTerminalControl(r) {
				found = append(found, r)
			}
		}
	}
	return found
}

func inspectHostileScreen(t *testing.T, what string, p tview.Primitive, width, height int, drawn, absent []string) {
	t.Helper()
	screen := drawPrimitive(t, p, width, height)
	text := screenText(screen)
	if raw := exposedControls(screen); len(raw) > 0 {
		t.Fatalf("%s exposed control runes %q in drawn cells:\n%s", what, raw, text)
	}
	for _, want := range drawn {
		if !strings.Contains(text, want) {
			t.Fatalf("%s did not draw %q:\n%s", what, want, text)
		}
	}
	for _, unwanted := range absent {
		if strings.Contains(text, unwanted) {
			t.Fatalf("%s drew %q:\n%s", what, unwanted, text)
		}
	}
}

func drawnRows(t *testing.T, p tview.Primitive) []string {
	t.Helper()
	cells, width, height := drawPrimitive(t, p, hostileScreenWidth, hostileScreenHeight).GetContents()
	rows := make([]string, height)
	for r := range rows {
		var b strings.Builder
		for _, c := range cells[r*width : (r+1)*width] {
			if len(c.Runes) == 0 {
				b.WriteRune(' ')
				continue
			}
			b.WriteString(string(c.Runes))
		}
		rows[r] = b.String()
	}
	return rows
}

func requireDrawnRows(t *testing.T, what string, p tview.Primitive, patterns ...string) {
	t.Helper()
	rows := drawnRows(t, p)
	for _, pattern := range patterns {
		if !slices.ContainsFunc(rows, regexp.MustCompile(pattern).MatchString) {
			t.Fatalf("%s drew no row matching %q:\n%s", what, pattern, strings.Join(rows, "\n"))
		}
	}
}

func requireDrawnBetween(t *testing.T, what string, p tview.Primitive, after, before, pattern string) {
	t.Helper()
	rows := drawnRows(t, p)
	start := slices.IndexFunc(rows, func(row string) bool { return strings.Contains(row, after) })
	if start < 0 {
		t.Fatalf("%s drew no row containing %q:\n%s", what, after, strings.Join(rows, "\n"))
	}
	end := slices.IndexFunc(rows[start+1:], func(row string) bool { return strings.Contains(row, before) })
	if end < 0 {
		t.Fatalf("%s drew no row containing %q after %q:\n%s", what, before, after, strings.Join(rows, "\n"))
	}
	region := strings.Join(rows[start+1:start+1+end], "\n")
	if !regexp.MustCompile(pattern).MatchString(region) {
		t.Fatalf("%s drew nothing matching %q between %q and %q:\n%s", what, pattern, after, before, region)
	}
}

func mountHostilePrompt(a *App, req PromptRequest) chan PromptDecision {
	decc := make(chan PromptDecision, 1)
	overlay, list := a.buildPromptOverlay(req, decc)
	a.pages.AddPage(promptBasePage, wrapOverlayPage(overlay), true, true)
	a.app.SetFocus(list)
	return decc
}

func pressFocused(a *App, ev *tcell.EventKey) {
	a.app.GetFocus().InputHandler()(ev, func(p tview.Primitive) { a.app.SetFocus(p) })
}

func pressRune(a *App, r rune) { pressFocused(a, tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone)) }

func pressFocusedEnter(a *App) { pressFocused(a, tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)) }

func selectFocusedRow(t *testing.T, a *App, prefix string) {
	t.Helper()
	list, ok := a.app.GetFocus().(*tview.List)
	if !ok {
		t.Fatalf("focus = %T, want a list", a.app.GetFocus())
	}
	for i := 0; i < list.GetItemCount(); i++ {
		if label, _ := list.GetItemText(i); strings.HasPrefix(label, prefix) {
			list.SetCurrentItem(i)
			pressFocusedEnter(a)
			return
		}
	}
	t.Fatalf("focused list has no row starting %q", prefix)
}

func requirePage(t *testing.T, a *App, page string) {
	t.Helper()
	if !a.pages.HasPage(page) {
		t.Fatalf("page %q is not mounted", page)
	}
}

func receivedDecision(t *testing.T, decc chan PromptDecision) PromptDecision {
	t.Helper()
	select {
	case d := <-decc:
		return d
	default:
		t.Fatal("the prompt sent no decision")
		return PromptDecision{}
	}
}

func withHostileFacts(req PromptRequest, v string) (PromptRequest, []string) {
	root := "/" + marked("PR", v)
	req.ProjectRoot = root
	req.LaunchDir = root
	req.Boundary = "launch-dir-only"
	req.WouldCreateSettingsFile = true
	req.RunFolder = root + "/" + marked("RF", v)
	req.FolderSettingsPath = "/" + marked("FS", v) + "/settings.yaml"
	req.FolderCoverage = marked("FC", v) + " and descendants"
	req.Note = marked("NO", v)
	req.ScopeEscalationNarrower = "/" + marked("NS", v)
	req.Summary = permissions.PromptSummaryResult{Kind: "request", Sentence: "Does something.", Effect: "unknown", Targets: []string{marked("RT", v)}}
	return req, []string{
		"Run folder: " + escapedControls(req.RunFolder),
		"Project root: " + escapedControls(root),
		"saved to " + escapedControls(req.FolderSettingsPath) + " so it survives restart.",
		"Applies when run from: " + escapedControls(req.FolderCoverage) + ".",
		escapedControls(req.Note),
		"PARENT of " + escapedControls(req.ScopeEscalationNarrower),
		"Requested target: " + escapedControls(marked("RT", v)),
		"created " + escapedControls(root+"/.codemeld/settings.yaml") + " — ",
	}
}

func hostileDirectRequest(v string) PromptRequest {
	return PromptRequest{
		Action:           "Run command",
		Subject:          marked("SU", v),
		Pipeline:         marked("PL", v),
		Kind:             SubjectDirectCommand,
		CanonicalProgram: marked("CP", v),
		CanonicalArgs:    []string{marked("CA", v)},
	}
}

type hostileOverlayVariant struct {
	name  string
	build func(v string) (PromptRequest, []string, []string)
}

func hostileOverlayVariants() []hostileOverlayVariant {
	withFacts := func(req PromptRequest, v string, rawTags ...string) (PromptRequest, []string, []string) {
		req, bounded := withHostileFacts(req, v)
		return req, markers(rawTags...), bounded
	}
	return []hostileOverlayVariant{
		{"direct", func(v string) (PromptRequest, []string, []string) {
			return withFacts(hostileDirectRequest(v), v, "SU", "PL")
		}},
		{"literal", func(v string) (PromptRequest, []string, []string) {
			req := PromptRequest{Action: "Run command", Subject: marked("SU", v), Kind: SubjectLiteralCommand, WholeCommand: true}
			return withFacts(req, v, "SU")
		}},
		{"batched", func(v string) (PromptRequest, []string, []string) {
			req := PromptRequest{
				Action:             "Run command",
				Subject:            marked("SU", v),
				Kind:               SubjectDirectCommand,
				Pipeline:           marked("PL", v),
				BatchedStages:      []string{marked("B1", v), marked("B2", v)},
				BatchedEscalations: []string{"/" + marked("E1", v), "/" + marked("E2", v)},
				BatchedNotes:       []string{marked("N1", v), marked("N2", v)},
			}
			req, raw, bounded := withFacts(req, v, "SU", "PL", "B1", "B2")
			return req, raw, append(bounded,
				"Stage 1: "+scopeEscalationNotice+escapedControls(req.BatchedEscalations[0]),
				"Stage 2: "+scopeEscalationNotice+escapedControls(req.BatchedEscalations[1]),
				"Stage 1: "+escapedControls(req.BatchedNotes[0]),
				"Stage 2: "+escapedControls(req.BatchedNotes[1]),
			)
		}},
		{"create", func(v string) (PromptRequest, []string, []string) {
			req := PromptRequest{Action: "Create file", Subject: marked("SU", v), Body: marked("BO", v), Kind: SubjectStructuredTool}
			return withFacts(req, v, "SU", "BO")
		}},
		{"edit", func(v string) (PromptRequest, []string, []string) {
			req := PromptRequest{Action: "Edit file", Subject: marked("SU", v), Body: "-" + marked("BM", v) + "\n+" + marked("BP", v), Kind: SubjectStructuredTool}
			return withFacts(req, v, "SU", "BM", "BP")
		}},
		{"mkdir", func(v string) (PromptRequest, []string, []string) {
			req := PromptRequest{Action: "Create directory", Subject: marked("SU", v), Kind: SubjectStructuredTool}
			return withFacts(req, v, "SU")
		}},
		{"host", func(v string) (PromptRequest, []string, []string) {
			req := PromptRequest{
				Kind:        SubjectHost,
				HostTool:    marked("HT", v),
				HostRequest: marked("HR", v),
				Host:        marked("HO", v),
				Summary:     permissions.PromptSummaryResult{Kind: "host request", Sentence: "Sends.", Effect: "contacts a host", Targets: []string{marked("RT", v)}},
			}
			return req, markers("HT", "HR"), []string{
				"Host: " + escapedControls(req.Host),
				"Requested target: " + escapedControls(marked("RT", v)),
			}
		}},
	}
}

func TestPromptOverlay_HostileControlsInEveryDisplayedField(t *testing.T) {
	for _, variant := range hostileOverlayVariants() {
		for _, hv := range hostileControls() {
			t.Run(variant.name+"/"+hv.name, func(t *testing.T) {
				req, raw, bounded := variant.build(hv.value)
				a := New(nil)
				mountHostilePrompt(a, req)
				inspectHostileScreen(t, "base overlay", a.pages, hostileScreenWidth, hostileScreenHeight, append(raw, bounded...), nil)
			})
		}
	}
}

func TestScopeChooser_HostileControlsThroughProgramConfirmation(t *testing.T) {
	flows := []struct {
		name          string
		mnemonic      rune
		option        PromptOption
		noCoverage    bool
		confirmMarker []string
	}{
		{"session", 's', OptionAllowSession, false, markers("CP", "FC")},
		{"folder", 'f', OptionAllowFolder, true, markers("CP", "FS", "PR", "RF")},
	}
	for _, flow := range flows {
		for _, hv := range hostileControls() {
			t.Run(flow.name+"/"+hv.name, func(t *testing.T) {
				req, _ := withHostileFacts(hostileDirectRequest(hv.value), hv.value)
				if flow.noCoverage {
					req.FolderCoverage = ""
				}
				a := New(nil)
				decc := mountHostilePrompt(a, req)

				pressRune(a, flow.mnemonic)
				requirePage(t, a, promptScopePage)
				inspectHostileScreen(t, "scope chooser", a.pages, hostileScreenWidth, hostileScreenHeight, nil, nil)
				requireDrawnRows(t, "scope chooser", a.pages,
					`^║ *exact: .*CP<.*>CP.*CA<.*>CA.* — only this exact command`,
					`^║ *prefix: .*CP<.*>CP.*CA<.*>CA.* :\* — fixed: .*CP<.*>CP.*CA<.*>CA.*; any later arguments may vary`,
					`^║ *program \(advanced\): .*CP<.*>CP.* :\* — ANY invocation of .*CP<.*>CP.* \(widest\)`,
				)

				selectFocusedRow(t, a, "program (advanced): ")
				requirePage(t, a, promptScopeConfirmPage)
				inspectHostileScreen(t, "program confirmation", a.pages, hostileScreenWidth, hostileScreenHeight, flow.confirmMarker, nil)

				pressFocusedEnter(a)
				d := receivedDecision(t, decc)
				if d.Option != flow.option || !strings.Contains(d.StoredSubject, req.CanonicalProgram) {
					t.Fatalf("decision = %+v, want option %d storing the unescaped program %q", d, flow.option, req.CanonicalProgram)
				}
			})
		}
	}
}

func TestScopeChooser_HostileControlsInThePathBoundary(t *testing.T) {
	for _, hv := range hostileControls() {
		t.Run(hv.name, func(t *testing.T) {
			if strings.ContainsRune(hv.value, 0) {
				t.Skip("unrepresentable: U+0000 cannot occur in a filename, so no real boundary can carry it")
			}
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("resolve temp root: %v", err)
			}
			home := filepath.Join(root, "home", "user")
			entry := filepath.Join(root, marked("BD", hv.value), "run", "id")
			if err := os.MkdirAll(home, 0o755); err != nil {
				t.Fatalf("mkdir home: %v", err)
			}
			if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
				t.Fatalf("mkdir run: %v", err)
			}
			if err := os.WriteFile(entry, nil, 0o644); err != nil {
				t.Fatalf("write entry: %v", err)
			}
			req, _ := withHostileFacts(PromptRequest{
				Action:           "Run command",
				Subject:          "chmod +x id",
				Kind:             SubjectDirectCommand,
				CanonicalProgram: "chmod",
				CanonicalArgs:    []string{"+x", entry},
			}, "")
			a := New(nil)
			a.SetHome(home)
			mountHostilePrompt(a, req)

			pressRune(a, 's')
			requirePage(t, a, promptScopePage)
			list, ok := a.app.GetFocus().(*tview.List)
			if !ok {
				t.Fatalf("focus = %T, want the scope list", a.app.GetFocus())
			}
			pathRow := -1
			for i := 0; i < list.GetItemCount(); i++ {
				if label, _ := list.GetItemText(i); strings.HasPrefix(label, "path: ") && strings.Contains(label, " against any path resolving under "+filepath.Dir(entry)+",") {
					pathRow = i
				}
			}
			if pathRow < 0 {
				t.Fatal("the scope chooser offers no path row bounded by the hostile directory")
			}
			inspectHostileScreen(t, "scope chooser", a.pages, hostileScreenWidth, hostileScreenHeight, nil, nil)
			boundary := regexp.MustCompile(regexp.QuoteMeta(" against any path resolving under "+root+"/BD<") + `[^\n]*?` + regexp.QuoteMeta(">BD/run,"))
			if text := screenText(drawPrimitive(t, a.pages, hostileScreenWidth, hostileScreenHeight)); !boundary.MatchString(text) {
				t.Fatalf("scope chooser did not draw the path row's boundary explanation with both BD markers:\n%s", text)
			}
		})
	}
}

func TestCompoundChooser_HostileControlsInStageTokens(t *testing.T) {
	for _, hv := range hostileControls() {
		t.Run(hv.name, func(t *testing.T) {
			sc := permissions.SimpleCompound{
				Stages:    [][]string{{marked("S1", hv.value), marked("A1", hv.value)}, {marked("S2", hv.value), "x"}},
				Operators: []string{"&&"},
			}
			req, _ := withHostileFacts(PromptRequest{Action: "Run command", Subject: marked("SU", hv.value), Kind: SubjectLiteralCommand, Compound: &sc}, hv.value)
			a := New(nil)
			decc := mountHostilePrompt(a, req)

			pressRune(a, 's')
			requirePage(t, a, promptCompoundPage)
			inspectHostileScreen(t, "compound stage 1", a.pages, hostileScreenWidth, hostileScreenHeight, append(markers("S1", "A1"), "compound stage 1 of 2"), nil)
			requireDrawnRows(t, "compound stage 1", a.pages,
				`^║ *exact: .*S1<.*>S1.*A1<.*>A1.* — only this exact command`,
				`^║ *subcommand: .*S1<.*>S1.*A1<.*>A1.* :\* — any command starting with .*S1<.*>S1.*A1<.*>A1`,
				`^║ *program \(advanced\): .*S1<.*>S1.* :\* — ANY invocation of .*S1<.*>S1.* \(widest\)`,
			)
			requireDrawnBetween(t, "compound stage 1 header", a.pages, "compound stage 1 of 2:", scopeProgramWarning, `(?s)S1<.*>S1.*A1<.*>A1`)

			pressFocusedEnter(a)
			requirePage(t, a, promptCompoundPage)
			inspectHostileScreen(t, "compound stage 2", a.pages, hostileScreenWidth, hostileScreenHeight, append(markers("S2"), "compound stage 2 of 2"), nil)
			requireDrawnRows(t, "compound stage 2", a.pages,
				`^║ *exact: .*S2<.*>S2.* x — only this exact command`,
				`^║ *subcommand: .*S2<.*>S2.* x :\* — any command starting with .*S2<.*>S2.* x`,
				`^║ *program \(advanced\): .*S2<.*>S2.* :\* — ANY invocation of .*S2<.*>S2.* \(widest\)`,
			)
			requireDrawnBetween(t, "compound stage 2 header", a.pages, "compound stage 2 of 2:", scopeProgramWarning, `(?s)S2<.*>S2.* x`)

			pressFocusedEnter(a)
			if d := receivedDecision(t, decc); d.Option != OptionAllowSession {
				t.Fatalf("decision = %+v, want the session option", d)
			}
		})
	}
}

func TestQuestionPrompt_HostileControlsInEveryDisplayedField(t *testing.T) {
	for _, hv := range hostileControls() {
		t.Run(hv.name, func(t *testing.T) {
			v := hv.value
			hostileContext := marked("CT", v)
			// The pad rows absorb the extra rows a raw VT draws beyond the options view's counted height, which would otherwise clip the hostile tail.
			spec := QuestionSpec{
				ID:                 "q",
				Prompt:             marked("QP", v),
				Context:            "CTok\n" + hostileContext,
				Options:            []string{marked("O1", v), marked("O2", v), "pad 1", "pad 2", "pad 3", "pad 4", "pad 5", "pad 6"},
				OptionDescriptions: []string{marked("D1", v), marked("D2", v)},
			}
			drawn := append(markers("QP", "O1", "O2", "D1", "D2"), "CTok")
			var absent []string
			for _, piece := range strings.Split(hostileContext, "\n") {
				for _, m := range markers("CT") {
					if !strings.Contains(piece, m) {
						continue
					}
					if strings.ContainsFunc(piece, isTerminalControl) {
						absent = append(absent, m)
					} else {
						drawn = append(drawn, m)
					}
				}
			}
			a := New(nil)
			openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{spec}})
			inspectHostileScreen(t, "question prompt", a.pages, 200, 60, drawn, absent)
		})
	}
}
