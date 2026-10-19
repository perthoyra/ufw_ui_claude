package ufw

import (
	"reflect"
	"strings"
	"testing"
)

const userRules = `*filter
:ufw-user-input - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=737368
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow_log any 80 0.0.0.0/0 any 10.0.0.0/8 in_eth0
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 Apache%20Full - in
### tuple ### route:deny any any 0.0.0.0/0 any 192.168.1.0/24 in_eth0!out_eth1
### tuple ### limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 out
### END RULES ###
`

const user6Rules = `### tuple ### allow tcp 22 ::/0 any ::/0 in comment=737368
`

const numbered = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # ssh
[ 2] 80 on eth0                 ALLOW IN    10.0.0.0/8                 (log)
[ 3] Apache Full                ALLOW IN    Anywhere
[ 4] Anywhere on eth1           DENY FWD    192.168.1.0/24 on eth0
[ 5] 2222/tcp                   LIMIT OUT   Anywhere (out)
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh
`

func TestParseTuples(t *testing.T) {
	v4, errs := ParseTuples(userRules, false)
	if len(errs) > 0 || len(v4) != 5 {
		t.Fatalf("got %d tuples, errs %v", len(v4), errs)
	}
	if v4[0].Comment != "ssh" || v4[0].Proto != "tcp" || v4[0].DPort != "22" {
		t.Errorf("tuple 0: %+v", v4[0])
	}
	if v4[1].Log != "log" || v4[1].IfaceIn != "eth0" || v4[1].Src != "10.0.0.0/8" {
		t.Errorf("tuple 1: %+v", v4[1])
	}
	if v4[2].DApp != "Apache Full" || v4[2].SApp != "" {
		t.Errorf("tuple 2: %+v", v4[2])
	}
	if !v4[3].Route || v4[3].IfaceIn != "eth0" || v4[3].IfaceOut != "eth1" || v4[3].Action != "deny" {
		t.Errorf("tuple 3: %+v", v4[3])
	}
}

func TestTupleArgs(t *testing.T) {
	v4, _ := ParseTuples(userRules, false)
	want := [][]string{
		{"allow", "in", "proto", "tcp", "from", "0.0.0.0/0", "to", "0.0.0.0/0", "port", "22", "comment", "ssh"},
		{"allow", "in", "on", "eth0", "log", "from", "10.0.0.0/8", "to", "0.0.0.0/0", "port", "80"},
		{"allow", "in", "from", "0.0.0.0/0", "to", "0.0.0.0/0", "app", "Apache Full"},
		{"route", "deny", "in", "on", "eth0", "out", "on", "eth1", "from", "192.168.1.0/24", "to", "0.0.0.0/0"},
		{"limit", "out", "proto", "tcp", "from", "0.0.0.0/0", "to", "0.0.0.0/0", "port", "2222"},
	}
	for i, w := range want {
		if got := v4[i].Args(); !reflect.DeepEqual(got, w) {
			t.Errorf("rule %d args\n got %q\nwant %q", i+1, got, w)
		}
	}
}

func TestParseNumberedAndMerge(t *testing.T) {
	n := ParseNumbered(numbered)
	if len(n) != 6 {
		t.Fatalf("got %d numbered rules", len(n))
	}
	if n[0].Comment != "ssh" || n[0].To != "22/tcp" || n[0].Action != "ALLOW IN" || n[0].From != "Anywhere" {
		t.Errorf("rule 1: %+v", n[0])
	}
	if n[3].Action != "DENY FWD" || n[3].To != "Anywhere on eth1" {
		t.Errorf("rule 4: %+v", n[3])
	}
	if !n[5].V6 || n[4].V6 {
		t.Errorf("v6 detection wrong")
	}
	v4, _ := ParseTuples(userRules, false)
	v6, _ := ParseTuples(user6Rules, true)
	rules := MergeRules(v4, v6, true, n)
	if len(rules) != 6 || rules[5].Tuple == nil || !rules[5].V6 || rules[5].To != "22/tcp (v6)" {
		t.Fatalf("merge: %+v", rules[5])
	}
	// inactive firewall: no numbered output, display strings synthesised
	rules = MergeRules(v4, v6, true, nil)
	if rules[0].To != "22/tcp" || rules[0].From != "Anywhere" || rules[5].To != "22/tcp (v6)" {
		t.Errorf("synthesised: %q / %q / %q", rules[0].To, rules[0].From, rules[5].To)
	}
}

func cmds(steps []Step) []string {
	var s []string
	for _, st := range steps {
		c := strings.Join(st.Args, " ")
		if st.RunIf != nil {
			if st.RunIf.OK {
				c = "ok? " + c
			} else {
				c = "fail? " + c
			}
		}
		s = append(s, c)
	}
	return s
}

func TestStepsMove(t *testing.T) {
	v4, _ := ParseTuples(userRules, false)
	v6, _ := ParseTuples(user6Rules, true)
	rules := MergeRules(v4, v6, true, nil)

	// move rule 5 (last v4) up to 1
	steps, err := StepsMove(rules, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--force delete 5",
		"ok? insert 1 limit out proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 2222",
		"fail? limit out proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 2222", // was last: restore appends
	}
	if got := cmds(steps); !reflect.DeepEqual(got, want) {
		t.Errorf("move 5->1\n got %q\nwant %q", got, want)
	}

	// move rule 2 down to the end of the v4 block: append
	steps, _ = StepsMove(rules, 2, 5)
	if got := cmds(steps)[1]; got != "ok? allow in on eth0 log from 10.0.0.0/8 to 0.0.0.0/0 port 80" {
		t.Errorf("move to end: %q", got)
	}
	if got := cmds(steps)[2]; got != "fail? insert 2 allow in on eth0 log from 10.0.0.0/8 to 0.0.0.0/0 port 80" {
		t.Errorf("restore: %q", got)
	}

	// cannot cross from v4 to v6
	if _, err := StepsMove(rules, 1, 6); err == nil {
		t.Error("expected family error")
	}
}

func TestScriptRoundTrip(t *testing.T) {
	steps := []Step{Ufw(false, "status"), Ufw(true, "--force", "delete", "3"), {Prog: "cat", Args: []string{"/x"}, RunIf: &Cond{Step: 1, OK: false}}}
	script, display := buildScript("N", "/usr/sbin/ufw", true, steps)
	if !strings.Contains(script, "/usr/sbin/ufw --dry-run --force delete 3") {
		t.Errorf("dry-run not applied:\n%s", script)
	}
	if !strings.Contains(script, `if [ "$r_1" != s ] && [ "$r_1" != 0 ]; then`) {
		t.Errorf("condition missing:\n%s", script)
	}
	out := "\n@@N:BEGIN:0@@\nStatus: active\n\n@@N:END:0:0@@\n\n@@N:BEGIN:1@@\nRule deleted\n\n@@N:END:1:0@@\n"
	res := parseScriptOutput("N", out, display)
	if res[0].Output != "Status: active\n" || res[0].ExitCode != 0 || !res[1].OK() || !res[2].Skipped {
		t.Errorf("results: %+v", res)
	}
	if ShellQuote("it's") != `'it'\''s'` || ShellQuote("22/tcp") != "22/tcp" || ShellQuote("") != "''" {
		t.Error("ShellQuote")
	}
}

func TestParseAppsAndReports(t *testing.T) {
	info := `Profile: Apache Full
Title: Web Server (HTTP,HTTPS)
Description: Apache v2 is the next generation of the omnipresent Apache web
server.

Ports:
  80,443/tcp

--

Profile: OpenSSH
Title: Secure shell server, an rshd replacement
Description: OpenSSH is a free implementation of the Secure Shell protocol.

Port:
  22/tcp
`
	apps := ParseAppInfo(info)
	if len(apps) != 2 || apps[0].Name != "Apache Full" || apps[0].Ports[0] != "80,443/tcp" ||
		!strings.HasSuffix(apps[0].Description, "web server.") || apps[1].Ports[0] != "22/tcp" {
		t.Errorf("apps: %+v", apps)
	}
	if got := ParseAppList("Available applications:\n  Apache Full\n  OpenSSH\n"); !reflect.DeepEqual(got, []string{"Apache Full", "OpenSSH"}) {
		t.Errorf("app list: %q", got)
	}
	listen := ParseListening("tcp:\n  22 * (sshd)\n   [ 1] allow 22/tcp\n\n  631 127.0.0.1 (cupsd)\nudp6:\n  5353 * (avahi-daemon)\n")
	if len(listen) != 3 || listen[0].Program != "sshd" || len(listen[0].Rules) != 1 || listen[2].Proto != "udp6" {
		t.Errorf("listening: %+v", listen)
	}
	added := ParseAdded("Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\nufw deny from 10.0.0.1\n")
	if !reflect.DeepEqual(added, []string{"allow 22/tcp", "deny from 10.0.0.1"}) {
		t.Errorf("added: %q", added)
	}
	s := &Snapshot{}
	parseVerbose(s, "Status: active\nLogging: on (medium)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n")
	if !s.Active || s.Logging != "medium" || s.DefaultIncoming != "deny" || s.DefaultOutgoing != "allow" || s.RoutedNote == "" || s.DefaultApp != "skip" {
		t.Errorf("verbose: %+v", s)
	}
}
