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

// overviewTab: enable/disable/reload/reset, default policies, logging, version.
type overviewTab struct {
	a          *App
	content    fyne.CanvasObject
	state      *widget.Label
	version    *widget.Label
	ipv6       *widget.Label
	ipv6Btn    *widget.Button
	routedNote *widget.Label
	enableBtn  *widget.Button
	disableBtn *widget.Button
	policy     map[string]*widget.Select
	logLevel   *widget.Select
	verbose    *widget.Label
}

func newOverviewTab(a *App) *overviewTab {
	t := &overviewTab{a: a, policy: map[string]*widget.Select{}}

	t.state = widget.NewLabel("Unknown")
	t.state.TextStyle.Bold = true
	t.version = widget.NewLabel("")
	t.ipv6 = widget.NewLabel("")
	t.enableBtn = widget.NewButtonWithIcon("Enable", theme.ConfirmIcon(), func() {
		a.confirm("Enable firewall", "Enable ufw and start it on boot?\n\nExisting SSH connections may be disrupted if no rule allows them.", func() {
			a.run("ufw enable", []ufw.Step{ufw.Ufw(true, "--force", "enable")}, true, nil)
		})
	})
	t.enableBtn.Importance = widget.HighImportance
	t.disableBtn = widget.NewButtonWithIcon("Disable", theme.CancelIcon(), func() {
		a.confirm("Disable firewall", "Stop ufw and disable it on boot?", func() {
			a.run("ufw disable", []ufw.Step{ufw.Ufw(true, "disable")}, true, nil)
		})
	})
	t.ipv6Btn = widget.NewButton("Enable IPv6", func() {
		on := a.snap == nil || a.snap.IPv6 != "yes"
		steps := ufw.StepsSetIPv6(on)
		v := "no"
		if on {
			v = "yes"
		}
		label := "set IPV6=" + v
		if a.runner.IsDryRun() {
			// sed has no dry-run mode; show what would run instead
			var cmds []string
			for _, st := range steps {
				prog := st.Prog
				if prog == "" {
					prog = "ufw"
				}
				cmds = append(cmds, ufw.CommandString(prog, st.Args))
			}
			a.showText("Dry run: "+label, "Dry-run mode is on, nothing was changed. Would run:\n\n"+strings.Join(cmds, "\n"))
			return
		}
		msg := "Set IPV6=" + v + " in /etc/default/ufw and reload ufw?"
		if on {
			msg += "\n\nIPv6 rules saved in " + ufw.IPv6RulesBackup + " (if present) are restored first."
		} else {
			msg += "\n\nThe IPv6 rules are saved to " + ufw.IPv6RulesBackup + " and restored when IPv6 is enabled here again.\nufw empties user6.rules while IPv6 is off, so enable IPv6 from this app to get them back."
		}
		a.confirm("IPv6", msg, func() {
			a.run(label, steps, true, nil)
		})
	})
	reload := widget.NewButtonWithIcon("Reload", theme.ViewRefreshIcon(), func() {
		a.run("ufw reload", []ufw.Step{ufw.Ufw(true, "reload")}, true, nil)
	})
	reset := widget.NewButtonWithIcon("Reset…", theme.DeleteIcon(), func() {
		a.confirm("Reset firewall", "Disable ufw and reset ALL rules and settings to installation defaults?\n\nufw backs up the current rule files with a timestamp suffix.", func() {
			a.run("ufw reset", []ufw.Step{ufw.Ufw(true, "--force", "reset")}, true, nil)
		})
	})
	reset.Importance = widget.DangerImportance

	stateCard := widget.NewCard("Firewall", "ufw enable | disable | reload | reset",
		container.NewVBox(
			container.NewHBox(widget.NewLabel("Status:"), t.state),
			container.NewHBox(t.enableBtn, t.disableBtn, reload, reset),
			container.NewHBox(widget.NewLabel("Version:"), t.version),
			container.NewHBox(widget.NewLabel("IPv6 (/etc/default/ufw):"), t.ipv6, t.ipv6Btn),
		))

	form := container.New(layout.NewFormLayout())
	for _, dir := range ufw.PolicyDirs {
		dir := dir
		sel := widget.NewSelect(ufw.Policies, nil)
		sel.PlaceHolder = "(unknown)"
		t.policy[dir] = sel
		apply := widget.NewButton("Apply", func() {
			if sel.Selected == "" {
				return
			}
			a.run("ufw default "+sel.Selected+" "+dir, []ufw.Step{ufw.Ufw(true, "default", sel.Selected, dir)}, true, nil)
		})
		form.Add(widget.NewLabel(capitalize(dir)))
		form.Add(container.NewBorder(nil, nil, nil, apply, sel))
	}
	t.routedNote = widget.NewLabel("")
	t.routedNote.Importance = widget.WarningImportance
	policyCard := widget.NewCard("Default policies", "ufw default allow|deny|reject incoming|outgoing|routed",
		container.NewVBox(form, t.routedNote))

	t.logLevel = widget.NewSelect(ufw.LogLevels, nil)
	t.logLevel.PlaceHolder = "(unknown)"
	logApply := widget.NewButton("Apply", func() {
		if t.logLevel.Selected == "" {
			return
		}
		a.run("ufw logging "+t.logLevel.Selected, []ufw.Step{ufw.Ufw(true, "logging", t.logLevel.Selected)}, true, nil)
	})
	logCard := widget.NewCard("Logging", "ufw logging on|off|low|medium|high|full",
		container.NewVBox(
			container.NewBorder(nil, nil, widget.NewLabel("Level"), logApply, t.logLevel),
			widget.NewLabel("'on' selects the default level (low)."),
		))

	t.verbose = monoLabel("")
	verboseCard := widget.NewCard("ufw status verbose", "", container.NewScroll(t.verbose))

	left := container.NewVBox(stateCard, policyCard, logCard)
	split := container.NewHSplit(container.NewVScroll(left), verboseCard)
	split.Offset = 0.45
	t.content = split
	return t
}

func (t *overviewTab) update(s *ufw.Snapshot) {
	if s.Active {
		t.state.SetText("Active")
		t.state.Importance = widget.SuccessImportance
		t.enableBtn.Disable()
		t.disableBtn.Enable()
	} else {
		t.state.SetText("Inactive")
		t.state.Importance = widget.DangerImportance
		t.enableBtn.Enable()
		t.disableBtn.Disable()
	}
	t.state.Refresh()
	t.version.SetText(s.Version)
	t.ipv6.SetText(s.IPv6)
	if s.IPv6 == "yes" {
		t.ipv6Btn.SetText("Disable IPv6")
	} else {
		t.ipv6Btn.SetText("Enable IPv6")
	}
	setSelect(t.policy["incoming"], s.DefaultIncoming)
	setSelect(t.policy["outgoing"], s.DefaultOutgoing)
	setSelect(t.policy["routed"], s.DefaultRouted)
	if s.RoutedNote != "" {
		t.routedNote.SetText("Routed: " + s.RoutedNote)
		t.routedNote.Show()
	} else {
		t.routedNote.Hide()
	}
	setSelect(t.logLevel, s.Logging)
	t.verbose.SetText(s.StatusVerbose)
}

// setSelect sets a Select's value without triggering a command.
func setSelect(sel *widget.Select, v string) {
	if v == "" {
		sel.ClearSelected()
		return
	}
	sel.SetSelected(v)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}
