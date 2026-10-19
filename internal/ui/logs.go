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

// logTab shows every command this session executed and its output.
// The log is kept in memory only.
type logTab struct {
	a       *App
	content fyne.CanvasObject
	table   *SortTable
	entries []ufw.LogEntry
	detail  *widget.Label
}

func newLogTab(a *App) *logTab {
	t := &logTab{a: a}
	t.table = NewSortTable([]Column{{"#", 50}, {"Time", 90}, {"Action", 260}, {"Result", 110}, {"Commands", 520}})
	t.detail = monoLabel("")
	t.table.OnSelected = func(i int) {
		if i < 0 || i >= len(t.entries) {
			t.detail.SetText("")
			return
		}
		e := t.entries[i]
		text := formatResults(e.Results)
		if e.Err != nil {
			text = "ERROR: " + e.Err.Error() + "\n\n" + text
		}
		t.detail.SetText(text)
	}
	clearBtn := widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), func() {
		t.entries = nil
		t.refresh()
	})
	split := container.NewVSplit(t.table.Table, container.NewScroll(t.detail))
	split.Offset = 0.45
	t.content = container.NewBorder(
		container.NewBorder(nil, nil, widget.NewLabel("Commands executed in this session (kept in memory only)"), clearBtn),
		nil, nil, nil, split)
	return t
}

func (t *logTab) add(e ufw.LogEntry) {
	t.entries = append(t.entries, e)
	t.refresh()
}

func (t *logTab) refresh() {
	rows := make([][]string, len(t.entries))
	for i, e := range t.entries {
		result := "ok"
		var cmds []string
		for _, r := range e.Results {
			if r.Skipped {
				continue
			}
			cmds = append(cmds, r.Command)
			if r.ExitCode != 0 {
				result = "failed"
			}
		}
		if e.Err != nil {
			result = "error"
		}
		rows[i] = []string{strconv.Itoa(i + 1), e.Time.Format("15:04:05"), e.Label, result, strings.Join(cmds, " ; ")}
	}
	t.table.SetRows(rows, -1)
	t.detail.SetText("")
}
