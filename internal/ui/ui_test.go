package ui

import (
	"testing"

	"fyne.io/fyne/v2/test"

	"ufwgui/internal/ufw"
)

func testSnapshot() *ufw.Snapshot {
	v4, _ := ufw.ParseTuples(`### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=737368
### tuple ### deny any any 0.0.0.0/0 any 10.0.0.0/8 in
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
`, false)
	v6, _ := ufw.ParseTuples("### tuple ### allow tcp 22 ::/0 any ::/0 in\n", true)
	return &ufw.Snapshot{
		Version: "ufw 0.36.2", Active: true, Logging: "low",
		DefaultIncoming: "deny", DefaultOutgoing: "allow", DefaultRouted: "deny", DefaultApp: "skip",
		Rules:    ufw.MergeRules(v4, v6, true, nil),
		TuplesOK: true,
		Apps:     []ufw.AppProfile{{Name: "OpenSSH", Title: "Secure shell", Ports: []string{"22/tcp"}}},
	}
}

func TestUI(t *testing.T) {
	fa := test.NewApp()
	defer fa.Quit()
	a := New(fa, ufw.PrivNone)
	s := testSnapshot()
	a.snap = s
	a.overview.update(s)
	a.rules.update(s)
	a.apps.update(s)

	if got := a.overview.policy["incoming"].Selected; got != "deny" {
		t.Errorf("incoming policy shown as %q", got)
	}

	rt := a.rules
	rt.table.SelectData(1) // rule 2, middle of the IPv4 block
	if r, ok := rt.selectedRule(); !ok || r.Number != 2 {
		t.Fatalf("selection: %+v %v", r, ok)
	}
	if rt.upBtn.Disabled() || rt.downBtn.Disabled() {
		t.Error("move buttons should be enabled for rule 2")
	}
	rt.table.SelectData(2) // rule 3: last IPv4 rule
	if !rt.downBtn.Disabled() {
		t.Error("down must be disabled at the end of the IPv4 block")
	}
	rt.table.SelectData(3) // the only IPv6 rule
	if !rt.upBtn.Disabled() || !rt.downBtn.Disabled() {
		t.Error("lone IPv6 rule must not move")
	}

	// sorting by a column disables manual moves and keeps the selection
	rt.table.SelectData(1)
	rt.table.cycleSort(1) // Action
	if rt.table.IsNaturalOrder() || !rt.upBtn.Disabled() {
		t.Error("moving must be disabled while sorted")
	}
	if rt.table.Selected() != 1 {
		t.Errorf("selection lost after sort: %d", rt.table.Selected())
	}
	rt.table.ResetSort()
	if !rt.table.IsNaturalOrder() || rt.upBtn.Disabled() {
		t.Error("rule order not restored")
	}

	// edit dialog pre-fills from the rule and previews delete + insert + restore
	r := s.Rules[0]
	f := showRuleDialog(a, placeReplace, &r, "")
	want := "ufw --force delete 1\nufw insert 1 allow in proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 22 comment ssh\nufw insert 1 allow in proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 22 comment ssh    # only if the previous step failed (restore)"
	if f.preview.Text != want {
		t.Errorf("edit preview:\n%s", f.preview.Text)
	}

	// simple syntax add with an application profile
	f = showRuleDialog(a, placeAppend, nil, "OpenSSH")
	f.direction.SetSelected("in")
	f.log.SetSelected("log")
	if f.preview.Text != "ufw allow in log OpenSSH" {
		t.Errorf("simple preview: %q", f.preview.Text)
	}
	// full syntax route rule, prepended
	f.syntax.SetSelected(syntaxFull)
	f.route.SetChecked(true)
	f.ifaceIn.SetText("eth0")
	f.ifOut.SetText("eth1")
	f.fromAddr.SetText("10.0.0.0/8")
	f.toKind.SetSelected(kindPort)
	f.toVal.SetText("443")
	f.proto.SetSelected("tcp")
	f.comment.SetText("web out")
	f.placeSel.SetSelected(placementNames[placePrepend])
	if want := "ufw prepend route allow in on eth0 out on eth1 log proto tcp from 10.0.0.0/8 to any port 443 comment 'web out'"; f.preview.Text != want {
		t.Errorf("full preview:\n got %s\nwant %s", f.preview.Text, want)
	}

	if !a.apps.actionBtns[0].Disabled() {
		t.Error("app actions should be disabled without a selection")
	}
	a.apps.table.SelectData(0)
	if a.apps.actionBtns[0].Disabled() || a.apps.title.Text != "OpenSSH — Secure shell" {
		t.Error("app selection not reflected")
	}
}

func TestNaturalLess(t *testing.T) {
	if !naturalLess("9", "10") || !naturalLess("22/tcp", "443/tcp") || naturalLess("b", "A") {
		t.Error("naturalLess")
	}
}

func TestUnquoteArgs(t *testing.T) {
	got := unquoteArgs([]string{"allow", "22", "comment", "'my", "ssh", "rule'"})
	if len(got) != 4 || got[3] != "my ssh rule" {
		t.Errorf("%q", got)
	}
}
