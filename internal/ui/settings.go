package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"ufwgui/internal/ufw"
)

type settingsTab struct {
	a       *App
	content fyne.CanvasObject
}

var privilegeLabels = map[ufw.Privilege]string{
	ufw.PrivPkexec: "pkexec (graphical polkit prompt)",
	ufw.PrivSudo:   "sudo -n (needs NOPASSWD or a cached sudo ticket)",
	ufw.PrivNone:   "none (this program already runs as root)",
}

func newSettingsTab(a *App) *settingsTab {
	t := &settingsTab{a: a}
	path := widget.NewEntry()
	path.SetText(a.runner.UfwPath)

	var labels []string
	for _, p := range ufw.Privileges {
		labels = append(labels, privilegeLabels[p])
	}
	priv := widget.NewSelect(labels, nil)
	priv.SetSelected(privilegeLabels[a.runner.Privilege])

	save := widget.NewButton("Save", func() {
		p := a.runner.Privilege
		for k, v := range privilegeLabels {
			if v == priv.Selected {
				p = k
			}
		}
		ufwPath := strings.TrimSpace(path.Text)
		if ufwPath == "" {
			ufwPath = "/usr/sbin/ufw"
		}
		a.runner.SetConfig(ufwPath, p, a.runner.IsDryRun())
		prefs := a.fa.Preferences()
		prefs.SetString(prefUfwPath, ufwPath)
		prefs.SetString(prefPrivilege, string(p))
		a.setStatus("Settings saved")
		a.refresh()
	})
	save.Importance = widget.HighImportance

	form := widget.NewForm(
		widget.NewFormItem("ufw executable", path),
		widget.NewFormItem("Privilege escalation", priv),
	)
	about := widget.NewLabel(
		"Commands run in an elevated helper shell that is started once, so you authenticate at startup and again only if the privilege mode changes or authentication is cancelled.\n\n" +
			"Privacy: this program makes no network connections and sends no telemetry. " +
			"Settings are stored locally by Fyne's preferences store; the command log exists only in memory.")
	about.Wrapping = fyne.TextWrapWord
	t.content = container.NewVBox(
		widget.NewCard("Execution", "", container.NewVBox(form, save)),
		widget.NewCard("About", "", about),
	)
	return t
}
