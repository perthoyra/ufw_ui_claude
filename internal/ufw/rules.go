package ufw

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Tuple is a rule as stored by ufw in /etc/ufw/user.rules and user6.rules
// ("### tuple ###" lines). It holds everything needed to recreate the rule.
type Tuple struct {
	Route     bool
	Action    string // allow, deny, reject, limit
	Log       string // "", "log", "log-all"
	Proto     string // any, tcp, udp, ...
	DPort     string // any or port spec
	Dst       string // address/CIDR
	SPort     string
	Src       string
	DApp      string
	SApp      string
	Direction string // in, out
	IfaceIn   string
	IfaceOut  string
	Comment   string
	V6        bool
}

// ParseTuples extracts all tuples from a user rules file.
func ParseTuples(content string, v6 bool) ([]Tuple, []error) {
	var tuples []Tuple
	var errs []error
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		const prefix = "### tuple ###"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		t, err := ParseTuple(strings.TrimSpace(line[len(prefix):]), v6)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		tuples = append(tuples, t)
	}
	return tuples, errs
}

// ParseTuple parses the text following "### tuple ###".
func ParseTuple(s string, v6 bool) (Tuple, error) {
	t := Tuple{V6: v6}
	f := strings.Fields(s)
	if n := len(f); n > 0 && strings.HasPrefix(f[n-1], "comment=") {
		raw := strings.TrimPrefix(f[n-1], "comment=")
		if b, err := hex.DecodeString(raw); err == nil {
			t.Comment = string(b)
		} else {
			t.Comment = raw
		}
		f = f[:n-1]
	}
	if len(f) != 7 && len(f) != 9 {
		return t, fmt.Errorf("unrecognised tuple %q", s)
	}
	action := f[0]
	if strings.HasPrefix(action, "route:") {
		t.Route = true
		action = strings.TrimPrefix(action, "route:")
	}
	if i := strings.Index(action, "_"); i >= 0 {
		t.Log = action[i+1:]
		action = action[:i]
	}
	t.Action = action
	t.Proto, t.DPort, t.Dst, t.SPort, t.Src = f[1], f[2], f[3], f[4], f[5]
	dir := f[6]
	if len(f) == 9 {
		t.DApp, t.SApp, dir = decodeApp(f[6]), decodeApp(f[7]), f[8]
	}
	for i, part := range strings.Split(dir, "!") {
		name, iface, _ := strings.Cut(part, "_")
		if name != "in" && name != "out" {
			// bare interface name: treat as outgoing interface
			iface, name = part, "out"
		}
		if i == 0 {
			t.Direction = name
		}
		if iface != "" {
			if name == "in" {
				t.IfaceIn = iface
			} else {
				t.IfaceOut = iface
			}
		}
	}
	return t, nil
}

// appKey mirrors ufw's get_app_tuple: ufw stores an application rule as one
// tuple per protocol but numbers and displays it once. Empty for non-app rules.
func (t Tuple) appKey() string {
	if t.DApp == "" && t.SApp == "" {
		return ""
	}
	dst, src := t.DApp, t.SApp
	if t.DApp == "" {
		dst = t.DPort
	}
	if t.SApp == "" {
		src = t.SPort
	}
	k := dst + " " + t.Dst + " " + src + " " + t.Src
	if t.IfaceIn == "" && t.IfaceOut == "" {
		return k + " " + t.Direction
	}
	if t.IfaceIn != "" {
		k += " in_" + t.IfaceIn
	}
	if t.IfaceOut != "" {
		k += " out_" + t.IfaceOut
	}
	return k
}

func decodeApp(s string) string {
	if s == "-" {
		return ""
	}
	return strings.ReplaceAll(s, "%20", " ")
}

func isAnyAddr(a string) bool {
	return a == "" || a == "any" || a == "0.0.0.0/0" || a == "::/0"
}

// Args returns full-syntax ufw arguments recreating the tuple. Addresses are
// always explicit so the rule stays in the same IP family (v4 or v6).
func (t Tuple) Args() []string {
	var a []string
	if t.Route {
		a = append(a, "route")
	}
	a = append(a, t.Action)
	switch {
	case t.Route:
		if t.IfaceIn != "" {
			a = append(a, "in", "on", t.IfaceIn)
		}
		if t.IfaceOut != "" {
			a = append(a, "out", "on", t.IfaceOut)
		}
	case t.IfaceIn != "":
		a = append(a, "in", "on", t.IfaceIn)
	case t.IfaceOut != "":
		a = append(a, "out", "on", t.IfaceOut)
	case t.Direction != "":
		a = append(a, t.Direction)
	}
	if t.Log != "" {
		a = append(a, t.Log)
	}
	if t.Proto != "" && t.Proto != "any" && t.DApp == "" && t.SApp == "" {
		a = append(a, "proto", t.Proto)
	}
	a = append(a, "from", orAny(t.Src))
	if t.SApp != "" {
		a = append(a, "app", t.SApp)
	} else if t.SPort != "" && t.SPort != "any" {
		a = append(a, "port", t.SPort)
	}
	a = append(a, "to", orAny(t.Dst))
	if t.DApp != "" {
		a = append(a, "app", t.DApp)
	} else if t.DPort != "" && t.DPort != "any" {
		a = append(a, "port", t.DPort)
	}
	if t.Comment != "" {
		a = append(a, "comment", t.Comment)
	}
	return a
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func endpoint(addr, port, app, proto, iface string, v6 bool) string {
	s := ""
	if app != "" {
		s = app
	} else if port != "" && port != "any" {
		s = port
		if proto != "" && proto != "any" {
			s += "/" + proto
		}
	}
	if !isAnyAddr(addr) {
		if s != "" {
			s = addr + " " + s
		} else {
			s = addr
		}
	}
	if s == "" {
		s = "Anywhere"
	}
	if iface != "" {
		s += " on " + iface
	}
	if v6 {
		s += " (v6)"
	}
	return s
}

// Rule is one numbered user rule as shown by "ufw status numbered".
type Rule struct {
	Number  int
	To      string
	Action  string // e.g. "ALLOW IN"
	From    string
	Comment string
	V6      bool
	Tuple   *Tuple // nil if the rule files could not be read
}

// ActionWord returns ALLOW, DENY, REJECT or LIMIT.
func (r Rule) ActionWord() string {
	if r.Tuple != nil {
		return strings.ToUpper(r.Tuple.Action)
	}
	w, _, _ := strings.Cut(r.Action, " ")
	return w
}

// DirectionWord returns IN, OUT or FWD.
func (r Rule) DirectionWord() string {
	if r.Tuple != nil {
		if r.Tuple.Route {
			return "FWD"
		}
		return strings.ToUpper(r.Tuple.Direction)
	}
	_, d, _ := strings.Cut(r.Action, " ")
	return d
}

// Family returns "IPv4" or "IPv6".
func (r Rule) Family() string {
	if r.V6 {
		return "IPv6"
	}
	return "IPv4"
}

var numberedRe = regexp.MustCompile(`^\[\s*(\d+)\]\s(.*?)\s+((?:ALLOW|DENY|REJECT|LIMIT)(?: (?:IN|OUT|FWD))?)\s+(.*?)(?:\s+# (.*))?$`)

// ParseNumbered parses "ufw status numbered" output.
func ParseNumbered(out string) []Rule {
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		m := numberedRe.FindStringSubmatch(strings.TrimRight(line, " \r"))
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		r := Rule{
			Number:  n,
			To:      strings.TrimSpace(m[2]),
			Action:  m[3],
			From:    strings.TrimSpace(m[4]),
			Comment: m[5],
		}
		r.V6 = strings.Contains(r.To, "(v6)") || strings.Contains(r.From, "(v6)")
		rules = append(rules, r)
	}
	return rules
}

// MergeRules combines tuples (authoritative order) with numbered status output
// (ufw's own display strings). Application tuples sharing an app key count as
// one rule, as in ufw. When tuples are unavailable the status output is used
// alone.
func MergeRules(v4, v6 []Tuple, tuplesOK bool, numbered []Rule) []Rule {
	if !tuplesOK {
		return numbered
	}
	byNum := map[int]Rule{}
	for _, r := range numbered {
		byNum[r.Number] = r
	}
	all := append(append([]Tuple{}, v4...), v6...)
	rules := make([]Rule, 0, len(all))
	seenApp := map[string]bool{}
	for i := range all {
		t := all[i]
		if k := t.appKey(); k != "" {
			if seenApp[k] {
				continue
			}
			seenApp[k] = true
		}
		r := Rule{Number: len(rules) + 1, V6: t.V6, Tuple: &t, Comment: t.Comment}
		if s, ok := byNum[r.Number]; ok && s.V6 == t.V6 {
			r.To, r.Action, r.From = s.To, s.Action, s.From
		} else {
			r.To = endpoint(t.Dst, t.DPort, t.DApp, t.Proto, t.IfaceIn, t.V6)
			r.From = endpoint(t.Src, t.SPort, t.SApp, t.Proto, "", t.V6)
			r.Action = strings.ToUpper(t.Action)
			if t.Route {
				r.Action += " FWD"
			} else if t.Direction != "" {
				r.Action += " " + strings.ToUpper(t.Direction)
			}
		}
		rules = append(rules, r)
	}
	return rules
}
