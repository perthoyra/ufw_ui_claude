package ui

import (
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"ufwgui/internal/ufw"
)

// reportsTab: ufw show REPORT and ufw status [verbose|numbered].
type reportsTab struct {
	a       *App
	content fyne.CanvasObject
	sel     *widget.Select
	raw     *widget.Label
	stack   *fyne.Container
	rawView fyne.CanvasObject

	listenTable *SortTable
	listenView  fyne.CanvasObject
	listening   []ufw.ListeningEntry

	addedTable *SortTable
	addedView  fyne.CanvasObject
	added      []string
}

var statusReports = []string{"status", "status verbose", "status numbered"}

func newReportsTab(a *App) *reportsTab {
	t := &reportsTab{a: a}
	var options []string
	for _, r := range ufw.Reports {
		options = append(options, "show "+r)
	}
	options = append(options, statusReports...)

	t.raw = monoLabel("Choose a report and press Run.")
	t.rawView = container.NewScroll(t.raw)

	t.listenTable = NewSortTable([]Column{{"Proto", 70}, {"Port", 80}, {"Address", 200}, {"Program", 180}, {"Matching rules", 420}})
	t.listenView = container.NewVSplit(t.listenTable.Table, container.NewScroll(t.raw))

	t.addedTable = NewSortTable([]Column{{"#", 50}, {"Command", 760}})
	delAdded := widget.NewButtonWithIcon("Delete this rule (ufw delete RULE)", theme.DeleteIcon(), func() {
		i := t.addedTable.Selected()
		if i < 0 || i >= len(t.added) {
			return
		}
		args := strings.Fields(t.added[i])
		args = unquoteArgs(args)
		a.confirm("Delete rule", "Run: ufw delete "+t.added[i]+"\n\nThis removes the matching IPv4 and IPv6 rules.", func() {
			a.run("ufw delete "+t.added[i], []ufw.Step{ufw.Ufw(true, append([]string{"--force", "delete"}, args...)...)}, true, func(res []ufw.Result, err error) {
				a.reportResult("Delete rule", res, err)
				t.runReport()
			})
		})
	})
	t.addedView = container.NewBorder(nil, delAdded, nil, nil, t.addedTable.Table)

	t.sel = widget.NewSelect(options, func(string) { t.runReport() })
	run := widget.NewButtonWithIcon("Run", theme.MediaPlayIcon(), t.runReport)
	copyBtn := widget.NewButtonWithIcon("Copy output", theme.ContentCopyIcon(), func() { a.fa.Clipboard().SetContent(t.raw.Text) })

	t.stack = container.NewStack(t.rawView)
	top := container.NewBorder(nil, nil, widget.NewLabel("Report:"), container.NewHBox(run, copyBtn), t.sel)
	t.content = container.NewBorder(top, nil, nil, nil, t.stack)
	return t
}

func (t *reportsTab) runReport() {
	choice := t.sel.Selected
	if choice == "" {
		return
	}
	args := strings.Fields(choice)
	t.a.run("ufw "+choice, []ufw.Step{ufw.Ufw(false, args...)}, false, func(res []ufw.Result, err error) {
		if err != nil || len(res) == 0 {
			t.a.reportResult("ufw "+choice, res, err)
			return
		}
		out := res[0].Output
		t.raw.SetText(out)
		t.a.setStatus("ufw " + choice + ": done")
		var view fyne.CanvasObject = t.rawView
		switch choice {
		case "show listening":
			t.listening = ufw.ParseListening(out)
			rows := make([][]string, len(t.listening))
			for i, e := range t.listening {
				rows[i] = []string{e.Proto, e.Port, e.Address, e.Program, strings.Join(e.Rules, "; ")}
			}
			t.listenTable.SetRows(rows, -1)
			view = t.listenView
		case "show added":
			t.added = ufw.ParseAdded(out)
			rows := make([][]string, len(t.added))
			for i, c := range t.added {
				rows[i] = []string{strconv.Itoa(i + 1), "ufw " + c}
			}
			t.addedTable.SetRows(rows, -1)
			view = t.addedView
		}
		t.stack.Objects = []fyne.CanvasObject{view}
		t.stack.Refresh()
	})
}

// unquoteArgs re-joins arguments that "ufw show added" printed in quotes
// (comments such as comment 'my rule').
func unquoteArgs(fields []string) []string {
	var out []string
	var cur []string
	quote := byte(0)
	for _, f := range fields {
		if quote == 0 && len(f) > 0 && (f[0] == '\'' || f[0] == '"') {
			quote = f[0]
			f = f[1:]
			cur = nil
		}
		if quote != 0 {
			if strings.HasSuffix(f, string(quote)) {
				cur = append(cur, strings.TrimSuffix(f, string(quote)))
				out = append(out, strings.Join(cur, " "))
				quote = 0
			} else {
				cur = append(cur, f)
			}
			continue
		}
		out = append(out, f)
	}
	if quote != 0 {
		out = append(out, strings.Join(cur, " "))
	}
	return out
}
