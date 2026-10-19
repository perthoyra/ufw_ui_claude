package ui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"ufwgui/internal/ufw"
)

type placement int

const (
	placeAppend placement = iota
	placeInsert
	placePrepend
	placeReplace // edit an existing rule in place
)

var placementNames = []string{"Append (end of list)", "Insert at position", "Prepend (top of list)"}

const (
	syntaxSimple = "Simple"
	syntaxFull   = "Full"
	kindNone     = "—"
	kindPort     = "port"
	kindApp      = "app"
	logNone      = "none"
	dirDefault   = "(default)"
)

// ruleForm holds the widgets of the rule builder.
type ruleForm struct {
	a       *App
	place   placement
	editing *ufw.Rule

	syntax                 *widget.RadioGroup
	route                  *widget.Check
	action, direction, log *widget.Select
	iface, ifaceIn, ifOut  *widget.Entry
	target                 *widget.SelectEntry
	proto                  *widget.Select
	fromAddr, toAddr       *widget.Entry
	fromKind, toKind       *widget.Select
	fromVal, toVal         *widget.SelectEntry
	comment                *widget.Entry
	placeSel               *widget.Select
	position               *widget.Entry
	preview                *widget.Label

	simpleRows, fullRows, routeRows, plainRows []fyne.CanvasObject
	posRow                                     []fyne.CanvasObject
}

// showRuleDialog opens the rule builder. editing is set for placeReplace;
// target pre-fills the simple-syntax port/app field.
func showRuleDialog(a *App, place placement, editing *ufw.Rule, target string) *ruleForm {
	f := &ruleForm{a: a, place: place, editing: editing}
	apps := a.appNames()

	f.syntax = widget.NewRadioGroup([]string{syntaxSimple, syntaxFull}, func(string) { f.layout() })
	f.syntax.Horizontal = true
	f.route = widget.NewCheck("Route / forward rule (ufw route …)", func(bool) { f.layout() })
	f.action = widget.NewSelect(ufw.Actions, func(string) { f.updatePreview() })
	f.direction = widget.NewSelect([]string{dirDefault, "in", "out"}, func(string) { f.updatePreview() })
	f.log = widget.NewSelect([]string{logNone, "log", "log-all"}, func(string) { f.updatePreview() })
	f.iface = f.entry("e.g. eth0 (optional)")
	f.ifaceIn = f.entry("incoming interface (optional)")
	f.ifOut = f.entry("outgoing interface (optional)")
	f.target = widget.NewSelectEntry(apps)
	f.target.PlaceHolder = "22, 22/tcp, 6000:6007/tcp, 80,443/tcp or application name"
	f.target.OnChanged = func(string) { f.updatePreview() }
	f.proto = widget.NewSelect(ufw.Protocols, func(string) { f.updatePreview() })
	f.fromAddr = f.entry("any, 192.168.0.0/24, 2001:db8::/32")
	f.toAddr = f.entry("any, 10.0.0.1")
	f.fromVal = widget.NewSelectEntry(apps)
	f.fromVal.OnChanged = func(string) { f.updatePreview() }
	f.toVal = widget.NewSelectEntry(apps)
	f.toVal.OnChanged = func(string) { f.updatePreview() }
	f.fromKind = widget.NewSelect([]string{kindNone, kindPort, kindApp}, func(string) { f.layout() })
	f.toKind = widget.NewSelect([]string{kindNone, kindPort, kindApp}, func(string) { f.layout() })
	f.comment = f.entry("optional")
	f.placeSel = widget.NewSelect(placementNames, func(string) { f.layout() })
	f.position = f.entry("rule number")
	f.preview = monoLabel("")
	f.preview.Wrapping = fyne.TextWrapBreak

	// defaults
	f.action.SetSelected("allow")
	f.direction.SetSelected(dirDefault)
	f.log.SetSelected(logNone)
	f.proto.SetSelected("any")
	f.fromAddr.SetText("any")
	f.toAddr.SetText("any")
	f.fromKind.SetSelected(kindNone)
	f.toKind.SetSelected(kindPort)
	f.target.SetText(target)
	f.syntax.SetSelected(syntaxSimple)
	if place != placeReplace {
		f.placeSel.SetSelected(placementNames[place])
	}
	if a.rules != nil {
		if r, ok := a.rules.selectedRule(); ok && place == placeInsert {
			f.position.SetText(strconv.Itoa(r.Number))
		}
	}
	if editing != nil && editing.Tuple != nil {
		f.fill(*editing.Tuple)
	}

	grid := container.New(layout.NewFormLayout())
	row := func(dst *[]fyne.CanvasObject, label string, w fyne.CanvasObject) {
		l := widget.NewLabel(label)
		grid.Add(l)
		grid.Add(w)
		*dst = append(*dst, l, w)
	}
	var common []fyne.CanvasObject
	row(&common, "Syntax", f.syntax)
	row(&f.fullRows, "", f.route)
	row(&common, "Action", f.action)
	row(&f.plainRows, "Direction", f.direction)
	row(&f.plainRows, "Interface", f.iface)
	row(&f.routeRows, "In on", f.ifaceIn)
	row(&f.routeRows, "Out on", f.ifOut)
	row(&common, "Logging", f.log)
	row(&f.simpleRows, "Port / app", f.target)
	row(&f.fullRows, "Protocol", f.proto)
	row(&f.fullRows, "From address", f.fromAddr)
	row(&f.fullRows, "From", container.NewBorder(nil, nil, f.fromKind, nil, f.fromVal))
	row(&f.fullRows, "To address", f.toAddr)
	row(&f.fullRows, "To", container.NewBorder(nil, nil, f.toKind, nil, f.toVal))
	row(&common, "Comment", f.comment)
	if place != placeReplace {
		row(&common, "Placement", f.placeSel)
		row(&f.posRow, "Position", f.position)
	}
	f.layout()

	title := "Add rule"
	okText := "Add"
	if place == placeReplace {
		title = fmt.Sprintf("Edit rule %d (%s)", editing.Number, editing.Family())
		okText = "Save"
	}
	var hint fyne.CanvasObject = widget.NewLabel("")
	if place == placeReplace {
		l := widget.NewLabel("The rule is replaced in place (delete + insert). Keep explicit addresses (0.0.0.0/0 or ::/0) to keep the rule in the same IP family; 'any' adds IPv4 and IPv6 rules.")
		l.Wrapping = fyne.TextWrapWord
		l.Importance = widget.LowImportance
		hint = l
	}
	content := container.NewBorder(nil,
		container.NewVBox(widget.NewSeparator(), widget.NewLabel("Command preview:"), f.preview, hint),
		nil, nil, container.NewVScroll(grid))

	d := dialog.NewCustomWithoutButtons(title, content, a.win)
	cancel := widget.NewButton("Cancel", d.Hide)
	test := widget.NewButton("Test (dry run)", func() { f.execute(true, false, nil) })
	buttons := []fyne.CanvasObject{cancel, test}
	if place != placeReplace {
		del := widget.NewButton("Delete matching rule", func() { f.execute(false, true, d) })
		del.Importance = widget.DangerImportance
		buttons = append(buttons, del)
	}
	ok := widget.NewButton(okText, func() { f.execute(false, false, d) })
	ok.Importance = widget.HighImportance
	buttons = append(buttons, ok)
	d.SetButtons(buttons)
	d.Resize(fyne.NewSize(760, 640))
	d.Show()
	return f
}

func (f *ruleForm) entry(placeholder string) *widget.Entry {
	e := widget.NewEntry()
	e.PlaceHolder = placeholder
	e.OnChanged = func(string) { f.updatePreview() }
	return e
}

// fill pre-populates the full-syntax fields from an existing rule.
func (f *ruleForm) fill(t ufw.Tuple) {
	f.syntax.SetSelected(syntaxFull)
	f.route.SetChecked(t.Route)
	f.action.SetSelected(t.Action)
	if t.Direction != "" {
		f.direction.SetSelected(t.Direction)
	}
	if t.Log != "" {
		f.log.SetSelected(t.Log)
	}
	if t.Route {
		f.ifaceIn.SetText(t.IfaceIn)
		f.ifOut.SetText(t.IfaceOut)
	} else if t.IfaceIn != "" {
		f.iface.SetText(t.IfaceIn)
	} else {
		f.iface.SetText(t.IfaceOut)
	}
	if t.Proto != "" && t.DApp == "" && t.SApp == "" {
		f.proto.SetSelected(t.Proto)
	}
	f.fromAddr.SetText(t.Src)
	f.toAddr.SetText(t.Dst)
	setKind := func(kind *widget.Select, val *widget.SelectEntry, port, app string) {
		switch {
		case app != "":
			kind.SetSelected(kindApp)
			val.SetText(app)
		case port != "" && port != "any":
			kind.SetSelected(kindPort)
			val.SetText(port)
		default:
			kind.SetSelected(kindNone)
		}
	}
	setKind(f.fromKind, f.fromVal, t.SPort, t.SApp)
	setKind(f.toKind, f.toVal, t.DPort, t.DApp)
	f.comment.SetText(t.Comment)
}

func setVisible(objs []fyne.CanvasObject, on bool) {
	for _, o := range objs {
		if on {
			o.Show()
		} else {
			o.Hide()
		}
	}
}

func (f *ruleForm) layout() {
	if f.preview == nil || f.placeSel == nil {
		return // still constructing
	}
	full := f.syntax.Selected == syntaxFull
	setVisible(f.simpleRows, !full)
	setVisible(f.fullRows, full)
	setVisible(f.routeRows, full && f.route.Checked)
	setVisible(f.plainRows, !(full && f.route.Checked))
	setVisible(f.posRow, f.placeSel.Selected == placementNames[placeInsert])
	if f.fromKind.Selected == kindNone {
		f.fromVal.Hide()
	} else {
		f.fromVal.Show()
	}
	if f.toKind.Selected == kindNone {
		f.toVal.Hide()
	} else {
		f.toVal.Show()
	}
	f.updatePreview()
}

// args builds the ufw rule arguments (without insert/prepend/delete).
func (f *ruleForm) args() ([]string, error) {
	var a []string
	full := f.syntax.Selected == syntaxFull
	route := full && f.route.Checked
	if route {
		a = append(a, "route")
	}
	if f.action.Selected == "" {
		return nil, errors.New("choose an action")
	}
	a = append(a, f.action.Selected)
	if route {
		if v := strings.TrimSpace(f.ifaceIn.Text); v != "" {
			a = append(a, "in", "on", v)
		}
		if v := strings.TrimSpace(f.ifOut.Text); v != "" {
			a = append(a, "out", "on", v)
		}
	} else {
		dir := f.direction.Selected
		iface := strings.TrimSpace(f.iface.Text)
		if iface != "" && (dir == dirDefault || dir == "") {
			dir = "in"
		}
		if dir != dirDefault && dir != "" {
			a = append(a, dir)
			if iface != "" {
				a = append(a, "on", iface)
			}
		}
	}
	if l := f.log.Selected; l != "" && l != logNone {
		a = append(a, l)
	}
	if !full {
		tgt := strings.TrimSpace(f.target.Text)
		if tgt == "" {
			return nil, errors.New("enter a port (e.g. 22/tcp) or an application name")
		}
		a = append(a, tgt)
	} else {
		usesApp := f.fromKind.Selected == kindApp || f.toKind.Selected == kindApp
		if p := f.proto.Selected; p != "" && p != "any" && !usesApp {
			a = append(a, "proto", p)
		}
		part := func(dir, addr string, kind *widget.Select, val *widget.SelectEntry) error {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				addr = "any"
			}
			a = append(a, dir, addr)
			if kind.Selected != kindNone {
				v := strings.TrimSpace(val.Text)
				if v == "" {
					return fmt.Errorf("enter the %s %s", dir, kind.Selected)
				}
				a = append(a, kind.Selected, v)
			}
			return nil
		}
		if err := part("from", f.fromAddr.Text, f.fromKind, f.fromVal); err != nil {
			return nil, err
		}
		if err := part("to", f.toAddr.Text, f.toKind, f.toVal); err != nil {
			return nil, err
		}
	}
	if c := strings.TrimSpace(f.comment.Text); c != "" {
		a = append(a, "comment", c)
	}
	return a, nil
}

// steps returns the commands for the chosen placement, or for deletion.
func (f *ruleForm) steps(del bool) ([]ufw.Step, string, error) {
	args, err := f.args()
	if err != nil {
		return nil, "", err
	}
	if del {
		return []ufw.Step{ufw.Ufw(true, append([]string{"--force", "delete"}, args...)...)}, "Delete matching rule", nil
	}
	if f.place == placeReplace {
		steps, err := ufw.StepsReplace(f.a.rules.rules, f.editing.Number, args)
		return steps, fmt.Sprintf("Edit rule %d", f.editing.Number), err
	}
	switch f.placeSel.Selected {
	case placementNames[placeInsert]:
		n, err := strconv.Atoi(strings.TrimSpace(f.position.Text))
		if err != nil || n < 1 {
			return nil, "", errors.New("enter a valid rule position (1 or higher)")
		}
		return []ufw.Step{ufw.Ufw(true, append([]string{"insert", strconv.Itoa(n)}, args...)...)}, fmt.Sprintf("Insert rule at %d", n), nil
	case placementNames[placePrepend]:
		return []ufw.Step{ufw.Ufw(true, append([]string{"prepend"}, args...)...)}, "Prepend rule", nil
	}
	return []ufw.Step{ufw.Ufw(true, args...)}, "Add rule", nil
}

func (f *ruleForm) updatePreview() {
	if f.preview == nil || f.placeSel == nil {
		return
	}
	steps, _, err := f.steps(false)
	if err != nil {
		f.preview.SetText("— " + err.Error())
		return
	}
	var lines []string
	for _, s := range steps {
		cmd := ufw.CommandString("ufw", s.Args)
		if s.RunIf != nil && !s.RunIf.OK {
			cmd += "    # only if the previous step failed (restore)"
		}
		lines = append(lines, cmd)
	}
	f.preview.SetText(strings.Join(lines, "\n"))
}

// execute runs the rule commands. test forces --dry-run for this call only.
func (f *ruleForm) execute(test, del bool, d dialog.Dialog) {
	steps, label, err := f.steps(del)
	if err != nil {
		dialog.ShowError(err, f.a.win)
		return
	}
	if test {
		for i := range steps {
			if steps[i].Prog == "" && steps[i].Mutating {
				steps[i].Args = append([]string{"--dry-run"}, steps[i].Args...)
				steps[i].Mutating = false
			}
		}
		f.a.run(label+" (test)", steps, false, func(res []ufw.Result, err error) {
			if err != nil {
				dialog.ShowError(err, f.a.win)
				return
			}
			f.a.showOutput(label+" (dry run)", res)
		})
		return
	}
	f.a.run(label, steps, true, func(res []ufw.Result, err error) {
		if f.a.reportResult(label, res, err) && d != nil {
			d.Hide()
		}
	})
}

// showForm shows a simple form dialog.
func showForm(a *App, title, confirm string, items []*widget.FormItem, onOK func()) {
	dialog.ShowForm(title, confirm, "Cancel", items, func(ok bool) {
		if ok {
			onOK()
		}
	}, a.win)
}
