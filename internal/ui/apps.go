package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"ufwgui/internal/ufw"
)

// appsTab: ufw app list | info | update [--add-new] | default, plus quick rules.
type appsTab struct {
	a       *App
	content fyne.CanvasObject
	table   *SortTable
	apps    []ufw.AppProfile

	title, desc, ports *widget.Label
	actionBtns         []*widget.Button
	defaultSel         *widget.Select
}

func newAppsTab(a *App) *appsTab {
	t := &appsTab{a: a}
	t.table = NewSortTable([]Column{{"Profile", 220}, {"Title", 340}, {"Ports", 260}})
	t.table.OnSelected = func(int) { t.showSelected() }

	t.title = widget.NewLabel("")
	t.title.TextStyle.Bold = true
	t.title.Wrapping = fyne.TextWrapWord
	t.desc = widget.NewLabel("")
	t.desc.Wrapping = fyne.TextWrapWord
	t.ports = monoLabel("")

	quick := func(action string) *widget.Button {
		return widget.NewButton(capitalize(action), func() {
			if p, ok := t.selected(); ok {
				a.run("ufw "+action+" "+p.Name, []ufw.Step{ufw.Ufw(true, action, p.Name)}, true, nil)
			}
		})
	}
	custom := widget.NewButtonWithIcon("Rule…", theme.ContentAddIcon(), func() {
		if p, ok := t.selected(); ok {
			showRuleDialog(a, placeAppend, nil, p.Name)
		}
	})
	info := widget.NewButtonWithIcon("Info", theme.InfoIcon(), func() {
		if p, ok := t.selected(); ok {
			a.run("ufw app info "+p.Name, []ufw.Step{ufw.Ufw(false, "app", "info", p.Name)}, false, func(res []ufw.Result, err error) {
				if err == nil && len(res) > 0 {
					a.showText("ufw app info "+p.Name, res[0].Output)
				} else {
					a.reportResult("ufw app info", res, err)
				}
			})
		}
	})
	update := widget.NewButton("Update", func() {
		if p, ok := t.selected(); ok {
			a.run("ufw app update "+p.Name, []ufw.Step{ufw.Ufw(true, "app", "update", p.Name)}, true, nil)
		}
	})
	addNew := widget.NewButton("Update --add-new", func() {
		if p, ok := t.selected(); ok {
			a.run("ufw app update --add-new "+p.Name, []ufw.Step{ufw.Ufw(true, "app", "update", "--add-new", p.Name)}, true, nil)
		}
	})
	t.actionBtns = []*widget.Button{quick("allow"), quick("deny"), quick("reject"), quick("limit"), custom, info, update, addNew}

	detail := widget.NewCard("Profile", "ufw app info",
		container.NewVBox(t.title, t.desc, widget.NewLabel("Ports:"), t.ports))
	rulesCard := widget.NewCard("Rules for this profile", "ufw allow|deny|reject|limit PROFILE",
		container.NewGridWithColumns(4, t.actionBtns[0], t.actionBtns[1], t.actionBtns[2], t.actionBtns[3]))
	maintCard := widget.NewCard("Maintenance", "ufw app update [--add-new] PROFILE",
		container.NewVBox(
			container.NewGridWithColumns(3, custom, info, update),
			addNew,
			widget.NewLabel("Update reapplies the profile's ports to its rules after the profile file changed.\n--add-new also adds a rule for a new profile using the default policy below."),
		))
	updateAll := widget.NewButton("Update all profiles", func() {
		a.run("ufw app update all", []ufw.Step{ufw.Ufw(true, "app", "update", "all")}, true, nil)
	})

	t.defaultSel = widget.NewSelect(ufw.AppPolicies, nil)
	t.defaultSel.PlaceHolder = "(unknown)"
	defApply := widget.NewButton("Apply", func() {
		if v := t.defaultSel.Selected; v != "" {
			a.run("ufw app default "+v, []ufw.Step{ufw.Ufw(true, "app", "default", v)}, true, nil)
		}
	})
	defCard := widget.NewCard("Default policy for new profiles", "ufw app default allow|deny|reject|skip",
		container.NewVBox(container.NewBorder(nil, nil, nil, defApply, t.defaultSel), updateAll))

	right := container.NewVScroll(container.NewVBox(detail, rulesCard, maintCard, defCard))
	split := container.NewHSplit(t.table.Table, right)
	split.Offset = 0.58
	t.content = container.NewBorder(
		container.NewHBox(widget.NewLabel("Application profiles in /etc/ufw/applications.d (ufw app list). Click a column header to sort."), layout.NewSpacer()),
		nil, nil, nil, split)
	t.showSelected()
	return t
}

func (t *appsTab) update(s *ufw.Snapshot) {
	keepName := ""
	if p, ok := t.selected(); ok {
		keepName = p.Name
	}
	t.apps = s.Apps
	rows := make([][]string, len(s.Apps))
	keep := -1
	for i, p := range s.Apps {
		rows[i] = []string{p.Name, p.Title, strings.Join(p.Ports, " ")}
		if p.Name == keepName {
			keep = i
		}
	}
	t.table.SetRows(rows, keep)
	setSelect(t.defaultSel, s.DefaultApp)
	t.showSelected()
}

func (t *appsTab) selected() (ufw.AppProfile, bool) {
	i := t.table.Selected()
	if i < 0 || i >= len(t.apps) {
		return ufw.AppProfile{}, false
	}
	return t.apps[i], true
}

func (t *appsTab) showSelected() {
	p, ok := t.selected()
	for _, b := range t.actionBtns {
		if ok {
			b.Enable()
		} else {
			b.Disable()
		}
	}
	if !ok {
		t.title.SetText("Select a profile")
		t.desc.SetText("")
		t.ports.SetText("")
		return
	}
	title := p.Name
	if p.Title != "" {
		title += " — " + p.Title
	}
	t.title.SetText(title)
	t.desc.SetText(p.Description)
	t.ports.SetText(strings.Join(p.Ports, "\n"))
}
