package ui

import (
	"fmt"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"ufwgui/internal/ufw"
)

var ruleColumns = []Column{
	{"#", 50}, {"Action", 80}, {"Dir", 55}, {"To", 230}, {"From", 230},
	{"Proto", 65}, {"Interface", 110}, {"Log", 65}, {"Family", 65}, {"Comment", 200},
}

type rulesTab struct {
	a       *App
	content fyne.CanvasObject
	table   *SortTable
	rules   []ufw.Rule
	detail  *widget.Label
	hint    *widget.Label

	editBtn, deleteBtn              *widget.Button
	topBtn, upBtn, downBtn, botBtn *widget.Button
	pendingSelect                   int // rule number to select after refresh
}

func newRulesTab(a *App) *rulesTab {
	t := &rulesTab{a: a}
	t.table = NewSortTable(ruleColumns)
	t.table.OnSelected = func(int) { t.updateButtons() }
	t.table.OnSorted = t.updateButtons

	add := widget.NewButtonWithIcon("Add…", theme.ContentAddIcon(), func() { showRuleDialog(a, placeAppend, nil, "") })
	insert := widget.NewButtonWithIcon("Insert…", theme.ContentAddIcon(), func() { showRuleDialog(a, placeInsert, nil, "") })
	prepend := widget.NewButtonWithIcon("Prepend…", theme.ContentAddIcon(), func() { showRuleDialog(a, placePrepend, nil, "") })
	t.editBtn = widget.NewButtonWithIcon("Edit…", theme.DocumentCreateIcon(), t.edit)
	t.deleteBtn = widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), t.delete)
	t.deleteBtn.Importance = widget.DangerImportance
	t.topBtn = widget.NewButtonWithIcon("Top", theme.MoveUpIcon(), func() { t.moveTo(func(first, _, _ int) int { return first }) })
	t.upBtn = widget.NewButtonWithIcon("Up", theme.MenuDropUpIcon(), func() { t.moveTo(func(_, _, n int) int { return n - 1 }) })
	t.downBtn = widget.NewButtonWithIcon("Down", theme.MenuDropDownIcon(), func() { t.moveTo(func(_, _, n int) int { return n + 1 }) })
	t.botBtn = widget.NewButtonWithIcon("Bottom", theme.MoveDownIcon(), func() { t.moveTo(func(_, last, _ int) int { return last }) })
	moveTo := widget.NewButtonWithIcon("Move to…", theme.MailForwardIcon(), t.moveToNumber)
	resetSort := widget.NewButtonWithIcon("Rule order", theme.ListIcon(), func() { t.table.ResetSort() })

	toolbar := container.NewHBox(
		add, insert, prepend, widget.NewSeparator(),
		t.editBtn, t.deleteBtn, widget.NewSeparator(),
		t.topBtn, t.upBtn, t.downBtn, t.botBtn, moveTo, widget.NewSeparator(),
		resetSort,
	)
	t.hint = widget.NewLabel("")
	t.hint.Wrapping = fyne.TextWrapWord
	t.hint.Importance = widget.LowImportance
	t.detail = monoLabel("")
	t.detail.Wrapping = fyne.TextWrapBreak
	copyBtn := widget.NewButtonWithIcon("Copy command", theme.ContentCopyIcon(), func() {
		if t.detail.Text != "" {
			a.fa.Clipboard().SetContent(t.detail.Text)
		}
	})
	bottom := container.NewVBox(
		widget.NewSeparator(),
		container.NewBorder(nil, nil, widget.NewLabel("Command:"), copyBtn, t.detail),
		t.hint,
	)
	t.content = container.NewBorder(toolbar, bottom, nil, nil, t.table.Table)
	t.updateButtons()
	return t
}

func (t *rulesTab) update(s *ufw.Snapshot) {
	t.rules = s.Rules
	rows := make([][]string, len(s.Rules))
	for i, r := range s.Rules {
		proto, iface, log := "", "", ""
		if tp := r.Tuple; tp != nil {
			proto, log = tp.Proto, tp.Log
			switch {
			case tp.IfaceIn != "" && tp.IfaceOut != "":
				iface = "in " + tp.IfaceIn + " → out " + tp.IfaceOut
			case tp.IfaceIn != "":
				iface = "in " + tp.IfaceIn
			case tp.IfaceOut != "":
				iface = "out " + tp.IfaceOut
			}
			if tp.DApp != "" || tp.SApp != "" {
				proto = "(app)"
			}
		}
		rows[i] = []string{strconv.Itoa(r.Number), r.ActionWord(), r.DirectionWord(), r.To, r.From, proto, iface, log, r.Family(), r.Comment}
	}
	keep := -1
	if t.pendingSelect > 0 && t.pendingSelect <= len(rows) {
		keep = t.pendingSelect - 1
	} else if sel := t.table.Selected(); sel >= 0 && sel < len(rows) {
		keep = sel
	}
	t.pendingSelect = 0
	t.table.SetRows(rows, keep)
	if !s.TuplesOK {
		t.hint.SetText("Rule details could not be read from /etc/ufw/user*.rules, so editing and moving are disabled. Check the privilege settings.")
	}
	t.updateButtons()
}

func (t *rulesTab) selectedRule() (ufw.Rule, bool) {
	i := t.table.Selected()
	if i < 0 || i >= len(t.rules) {
		return ufw.Rule{}, false
	}
	return t.rules[i], true
}

func (t *rulesTab) updateButtons() {
	r, ok := t.selectedRule()
	enable := func(b *widget.Button, on bool) {
		if on {
			b.Enable()
		} else {
			b.Disable()
		}
	}
	enable(t.deleteBtn, ok)
	enable(t.editBtn, ok && r.Tuple != nil)
	movable := ok && r.Tuple != nil && t.table.IsNaturalOrder()
	first, last := 0, 0
	if ok {
		first, last = t.familyBounds(r)
	}
	enable(t.topBtn, movable && r.Number > first)
	enable(t.upBtn, movable && r.Number > first)
	enable(t.downBtn, movable && r.Number < last)
	enable(t.botBtn, movable && r.Number < last)

	if ok {
		if r.Tuple != nil {
			t.detail.SetText(ufw.CommandString("ufw", r.Tuple.Args()))
		} else {
			t.detail.SetText("")
		}
	} else {
		t.detail.SetText("")
	}
	if t.a.snap != nil && !t.a.snap.TuplesOK {
		return
	}
	if !t.table.IsNaturalOrder() {
		t.hint.SetText("The list is sorted by a column. Click \"Rule order\" (or the sorted header until the arrow disappears) to reorder rules manually.")
	} else {
		t.hint.SetText("Rules are evaluated top to bottom; the first match wins. ufw always lists IPv4 rules before IPv6 rules, so rules can only be moved within their own family. Moving is done as delete + insert; if the insert fails the original rule is restored.")
	}
}

func (t *rulesTab) familyBounds(r ufw.Rule) (int, int) {
	first, last := 0, 0
	for _, x := range t.rules {
		if x.V6 == r.V6 {
			if first == 0 {
				first = x.Number
			}
			last = x.Number
		}
	}
	return first, last
}

func (t *rulesTab) moveTo(target func(first, last, n int) int) {
	r, ok := t.selectedRule()
	if !ok {
		return
	}
	first, last := t.familyBounds(r)
	t.move(r, target(first, last, r.Number))
}

func (t *rulesTab) move(r ufw.Rule, to int) {
	if to == r.Number {
		return
	}
	steps, err := ufw.StepsMove(t.rules, r.Number, to)
	if err != nil {
		t.a.reportResult("Move rule", nil, err)
		return
	}
	label := fmt.Sprintf("Move rule %d to %d", r.Number, to)
	t.a.run(label, steps, true, func(res []ufw.Result, err error) {
		if t.a.reportResult(label, res, err) && !t.a.runner.IsDryRun() {
			t.pendingSelect = to
		}
	})
}

func (t *rulesTab) moveToNumber() {
	r, ok := t.selectedRule()
	if !ok || r.Tuple == nil || !t.table.IsNaturalOrder() {
		return
	}
	first, last := t.familyBounds(r)
	e := widget.NewEntry()
	e.SetText(strconv.Itoa(r.Number))
	showForm(t.a, fmt.Sprintf("Move rule %d", r.Number), "Move", []*widget.FormItem{
		{Text: "New position", Widget: e, HintText: fmt.Sprintf("%d–%d (%s rules)", first, last, r.Family())},
	}, func() {
		n, err := strconv.Atoi(e.Text)
		if err != nil || n < first || n > last {
			t.a.reportResult("Move rule", nil, fmt.Errorf("position must be between %d and %d", first, last))
			return
		}
		t.move(r, n)
	})
}

func (t *rulesTab) edit() {
	r, ok := t.selectedRule()
	if !ok || r.Tuple == nil {
		return
	}
	showRuleDialog(t.a, placeReplace, &r, "")
}

func (t *rulesTab) delete() {
	r, ok := t.selectedRule()
	if !ok {
		return
	}
	msg := fmt.Sprintf("Delete rule %d?\n\n%s %s  %s → %s", r.Number, r.ActionWord(), r.DirectionWord(), r.From, r.To)
	t.a.confirm("Delete rule", msg, func() {
		t.a.run(fmt.Sprintf("ufw delete %d", r.Number), ufw.StepsDeleteNumber(r.Number), true, nil)
	})
}
