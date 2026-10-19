// Package ui implements the Fyne user interface for ufw.
package ui

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"ufwgui/internal/ufw"
)

const (
	prefUfwPath   = "ufwPath"
	prefPrivilege = "privilege"
	prefDryRun    = "dryRun"
)

// App is the main window and shared state.
type App struct {
	fa     fyne.App
	win    fyne.Window
	runner *ufw.Runner
	snap   *ufw.Snapshot

	busyCount  atomic.Int32
	busy       *widget.ProgressBarInfinite
	statusText *widget.Label
	dryCheck   *widget.Check
	warnBtn    *widget.Button

	overview *overviewTab
	rules    *rulesTab
	apps     *appsTab
	reports  *reportsTab
	logs     *logTab
	settings *settingsTab
}

// New builds the main window.
func New(fa fyne.App, defaultPriv ufw.Privilege) *App {
	a := &App{fa: fa, runner: ufw.NewRunner()}
	p := fa.Preferences()
	a.runner.SetConfig(
		p.StringWithFallback(prefUfwPath, "/usr/sbin/ufw"),
		ufw.Privilege(p.StringWithFallback(prefPrivilege, string(defaultPriv))),
		p.BoolWithFallback(prefDryRun, false),
	)

	a.win = fa.NewWindow("Uncomplicated Firewall")
	a.logs = newLogTab(a)
	a.runner.OnLog = func(e ufw.LogEntry) { fyne.Do(func() { a.logs.add(e) }) }

	a.overview = newOverviewTab(a)
	a.rules = newRulesTab(a)
	a.apps = newAppsTab(a)
	a.reports = newReportsTab(a)
	a.settings = newSettingsTab(a)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Status & Policies", theme.HomeIcon(), a.overview.content),
		container.NewTabItemWithIcon("Rules", theme.ListIcon(), a.rules.content),
		container.NewTabItemWithIcon("Application Profiles", theme.StorageIcon(), a.apps.content),
		container.NewTabItemWithIcon("Reports", theme.DocumentIcon(), a.reports.content),
		container.NewTabItemWithIcon("Command Log", theme.HistoryIcon(), a.logs.content),
		container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), a.settings.content),
	)

	a.busy = widget.NewProgressBarInfinite()
	a.busy.Hide()
	a.statusText = widget.NewLabel("Ready")
	a.statusText.Truncation = fyne.TextTruncateEllipsis
	a.dryCheck = widget.NewCheck("Dry run (show changes, apply nothing)", func(on bool) {
		a.runner.SetConfig(a.runner.UfwPath, a.runner.Privilege, on)
		a.fa.Preferences().SetBool(prefDryRun, on)
		if on {
			a.setStatus("Dry-run mode: commands are passed --dry-run and change nothing")
		}
	})
	a.dryCheck.SetChecked(a.runner.IsDryRun())
	a.warnBtn = widget.NewButtonWithIcon("Warnings", theme.WarningIcon(), a.showWarnings)
	a.warnBtn.Importance = widget.WarningImportance
	a.warnBtn.Hide()

	top := container.NewHBox(
		widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), a.refresh),
		a.dryCheck,
		a.warnBtn,
	)
	bottom := container.NewBorder(nil, nil, nil, container.NewGridWrap(fyne.NewSize(120, 10), a.busy), a.statusText)
	a.win.SetContent(container.NewBorder(top, bottom, nil, nil, tabs))
	a.win.Resize(fyne.NewSize(1200, 760))
	return a
}

// ShowAndRun displays the window, loads the firewall state and runs the event loop.
func (a *App) ShowAndRun() {
	a.win.Show()
	a.refresh()
	a.fa.Run()
}

func (a *App) setStatus(s string) { a.statusText.SetText(s) }

func (a *App) setBusy(delta int32) {
	if a.busyCount.Add(delta) > 0 {
		a.busy.Show()
		a.busy.Start()
	} else {
		a.busy.Stop()
		a.busy.Hide()
	}
}

// run executes steps in the background. done (optional) runs on the UI
// goroutine. If refresh is set the firewall state is reloaded afterwards.
func (a *App) run(label string, steps []ufw.Step, refresh bool, done func([]ufw.Result, error)) {
	a.setBusy(1)
	a.setStatus(label + "…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		res, err := a.runner.Run(ctx, label, steps...)
		cancel()
		fyne.Do(func() {
			a.setBusy(-1)
			if done != nil {
				done(res, err)
			} else {
				a.reportResult(label, res, err)
			}
			if refresh {
				a.refresh()
			}
		})
	}()
}

// reportResult shows errors and dry-run output; success goes to the status bar.
func (a *App) reportResult(label string, res []ufw.Result, err error) bool {
	if err != nil {
		a.setStatus(label + ": failed")
		dialog.ShowError(err, a.win)
		return false
	}
	var failed []ufw.Result
	for _, r := range res {
		if !r.Skipped && r.ExitCode != 0 {
			failed = append(failed, r)
		}
	}
	if len(failed) > 0 {
		a.setStatus(label + ": failed")
		a.showOutput(label+" failed", res)
		return false
	}
	if a.runner.IsDryRun() && anyMutating(res) {
		a.setStatus(label + ": dry run complete (no changes made)")
		a.showOutput(label+" (dry run)", res)
		return true
	}
	last := ""
	for _, r := range res {
		if out := strings.TrimSpace(r.Output); !r.Skipped && out != "" {
			last = lastLine(out)
		}
	}
	if last == "" {
		last = "done"
	}
	a.setStatus(label + ": " + last)
	return true
}

func anyMutating(res []ufw.Result) bool {
	for _, r := range res {
		if strings.Contains(r.Command, "--dry-run") {
			return true
		}
	}
	return false
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func formatResults(res []ufw.Result) string {
	var b strings.Builder
	for _, r := range res {
		switch {
		case r.Skipped:
			fmt.Fprintf(&b, "$ %s\n(skipped)\n\n", r.Command)
		default:
			fmt.Fprintf(&b, "$ %s\n%s\n[exit status %d]\n\n", r.Command, strings.TrimRight(r.Output, "\n"), r.ExitCode)
		}
	}
	return strings.TrimSpace(b.String())
}

func (a *App) showOutput(title string, res []ufw.Result) {
	a.showText(title, formatResults(res))
}

func (a *App) showText(title, text string) {
	l := monoLabel(text)
	scroll := container.NewScroll(l)
	scroll.SetMinSize(fyne.NewSize(720, 360))
	dialog.NewCustom(title, "Close", scroll, a.win).Show()
}

// confirm asks before a destructive action.
func (a *App) confirm(title, msg string, f func()) {
	dialog.ShowConfirm(title, msg, func(ok bool) {
		if ok {
			f()
		}
	}, a.win)
}

// refresh reloads the complete firewall state in one privileged call.
func (a *App) refresh() {
	a.run("Loading firewall state", ufw.SnapshotSteps(), false, func(res []ufw.Result, err error) {
		if err != nil {
			a.setStatus("Could not load firewall state")
			dialog.ShowError(fmt.Errorf("%w\n\nCheck the privilege settings in the Settings tab.", err), a.win)
			return
		}
		a.snap = ufw.ParseSnapshot(res)
		a.overview.update(a.snap)
		a.rules.update(a.snap)
		a.apps.update(a.snap)
		if len(a.snap.Warnings) > 0 {
			a.warnBtn.SetText(fmt.Sprintf("Warnings (%d)", len(a.snap.Warnings)))
			a.warnBtn.Show()
		} else {
			a.warnBtn.Hide()
		}
		state := "inactive"
		if a.snap.Active {
			state = "active"
		}
		a.setStatus(fmt.Sprintf("Firewall %s · %d rules · %d application profiles", state, len(a.snap.Rules), len(a.snap.Apps)))
	})
}

func (a *App) showWarnings() {
	if a.snap == nil {
		return
	}
	a.showText("Warnings", strings.Join(a.snap.Warnings, "\n\n"))
}

func (a *App) appNames() []string {
	if a.snap == nil {
		return nil
	}
	names := make([]string, len(a.snap.Apps))
	for i, p := range a.snap.Apps {
		names[i] = p.Name
	}
	return names
}

func monoLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.TextStyle = fyne.TextStyle{Monospace: true}
	return l
}
