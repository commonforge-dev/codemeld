package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const systemOnePickerPage = "systemone-picker"

type SystemOneChoice struct {
	Name     string
	Provider string
	ModelID  string
}

type SystemOneDeps struct {
	Current    func() string
	Set        func(name string) error
	Choices    []SystemOneChoice
	HasKey     func(provider string) bool
	Status     func() string
	OpenPicker func()
}

func NewSystemOneHandler(deps SystemOneDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		if len(args) == 0 {
			if deps.OpenPicker != nil {
				deps.OpenPicker()
				return nil
			}
			ctx.Notice(deps.status(true))
			return recordSystemOne(ctx, OutcomeSuccess, "")
		}
		notice, ok := deps.selectName(args[0])
		if !ok {
			return rejectSystemOne(ctx, notice)
		}
		ctx.Notice(notice)
		return recordSystemOne(ctx, OutcomeSuccess, "")
	}
}

func (deps SystemOneDeps) rowNames() []string {
	names := []string{"off"}
	for _, c := range deps.Choices {
		names = append(names, c.Name)
	}
	return names
}

func (deps SystemOneDeps) selectName(name string) (string, bool) {
	confirm := "System One turned off"
	if name != "off" {
		choice, ok := deps.choice(name)
		if !ok {
			return "usage: /systemone <" + strings.Join(deps.rowNames(), "|") + ">", false
		}
		if !deps.HasKey(choice.Provider) {
			return "System One: " + choice.Provider + " has no API key; run /connect " + choice.Provider, false
		}
		confirm = "System One set to " + name
	}
	if err := deps.Set(name); err != nil {
		return renderSettingFailedNotice("System One", err), false
	}
	return confirm, true
}

func (deps SystemOneDeps) choice(name string) (SystemOneChoice, bool) {
	for _, c := range deps.Choices {
		if c.Name == name {
			return c, true
		}
	}
	return SystemOneChoice{}, false
}

func (deps SystemOneDeps) status(withChoices bool) string {
	current := deps.Current()
	segments := []string{"System One: " + current, "applies only in Plan and Auto edits"}
	if c, ok := deps.choice(current); ok {
		segments[0] = fmt.Sprintf("System One: %s (provider %s, model %s)", c.Name, c.Provider, c.ModelID)
		key := "API key: configured"
		if !deps.HasKey(c.Provider) {
			key = "API key: none, run /connect " + c.Provider
		}
		segments = append(segments, key)
	}
	if withChoices {
		segments = append(segments, "choices: "+strings.Join(deps.rowNames(), ", "))
	}
	if deps.Status != nil {
		if line := deps.Status(); line != "" {
			segments = append(segments, line)
		}
	}
	return strings.Join(segments, "; ")
}

func rejectSystemOne(ctx CommandContext, notice string) error {
	ctx.Notice(notice)
	ctx.RetainInput()
	return recordSystemOne(ctx, OutcomeError, notice)
}

func recordSystemOne(ctx CommandContext, outcome Outcome, detail string) error {
	if err := ctx.AppendSlashCommand(outcome, detail); err != nil {
		return err
	}
	return ctx.FlushActive()
}

func (a *App) OpenSystemOnePicker() {
	deps := a.systemOneDeps
	if a.anyOverlayOpen() || deps.Current == nil || deps.Set == nil || deps.HasKey == nil {
		return
	}
	current := deps.Current()
	rows := deps.rowNames()
	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	for _, name := range rows {
		label := name
		if c, ok := deps.choice(name); ok && !deps.HasKey(c.Provider) {
			label += "  no API key, run /connect " + c.Provider
		}
		list.AddItem(label, "", 0, nil)
	}
	list.SetCurrentItem(max(0, slices.Index(rows, current)))
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) {
		a.confirmSystemOneSelection(rows[index])
	})

	status := deps.status(false)
	header := tview.NewTextView()
	header.SetWrap(true)
	header.SetWordWrap(true)
	header.SetText(status)
	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(list, len(rows), 0, true)
	body.SetBorder(true)
	body.SetTitle(" System One ")
	headerRows := 1
	body.SetDrawFunc(func(_ tcell.Screen, x, y, width, height int) (int, int, int, int) {
		if n := len(wrapRows(status, width-2)); n > 0 && n != headerRows {
			headerRows = n
			body.ResizeItem(header, n, 0)
		}
		return x + 1, y + 1, max(0, width-2), max(0, height-2)
	})

	a.systemOnePickerOpen = true
	a.systemOnePickerStatus = status
	a.systemOnePickerPrev = a.app.GetFocus()
	a.pages.AddPage(systemOnePickerPage, wrapOverlayPage(body), true, true)
	a.app.SetFocus(list)
}

func (a *App) SystemOnePickerOpen() bool { return a.systemOnePickerOpen }

func (a *App) SystemOnePickerStatusText() string {
	if !a.systemOnePickerOpen {
		return ""
	}
	return a.systemOnePickerStatus
}

func (a *App) SelectSystemOneRowForTest(name string) bool {
	if !a.systemOnePickerOpen || !slices.Contains(a.systemOneDeps.rowNames(), name) {
		return false
	}
	a.confirmSystemOneSelection(name)
	return true
}

func (a *App) confirmSystemOneSelection(name string) {
	a.dismissSystemOnePicker()
	if name == a.systemOneDeps.Current() {
		return
	}
	notice, _ := a.systemOneDeps.selectName(name)
	a.Notice(notice)
}

func (a *App) dismissSystemOnePicker() {
	if !a.systemOnePickerOpen {
		return
	}
	a.systemOnePickerOpen = false
	a.closeOverlayPage(systemOnePickerPage, &a.systemOnePickerPrev)
}
