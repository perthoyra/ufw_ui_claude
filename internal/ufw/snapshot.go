package ufw

import (
	"regexp"
	"strings"
)

// AppProfile is an application profile from /etc/ufw/applications.d.
type AppProfile struct {
	Name        string
	Title       string
	Description string
	Ports       []string
}

// Snapshot is the parsed state of the firewall.
type Snapshot struct {
	Version         string
	Active          bool
	StatusVerbose   string
	Logging         string
	DefaultIncoming string
	DefaultOutgoing string
	DefaultRouted   string
	RoutedNote      string
	DefaultApp      string
	IPv6            string
	Rules           []Rule
	TuplesOK        bool
	Apps            []AppProfile
	Warnings        []string
}

// ParseSnapshot builds a Snapshot from the results of SnapshotSteps.
func ParseSnapshot(res []Result) *Snapshot {
	s := &Snapshot{}
	get := func(i int) (string, bool) {
		if i >= len(res) {
			return "", false
		}
		return res[i].Output, res[i].OK()
	}
	warn := func(i int, what string) {
		if i < len(res) {
			msg := strings.TrimSpace(res[i].Output)
			if msg == "" {
				msg = "no output"
			}
			s.Warnings = append(s.Warnings, what+": "+msg)
		}
	}

	if out, ok := get(0); ok {
		s.Version, _, _ = strings.Cut(strings.TrimSpace(out), "\n")
	} else {
		warn(0, "ufw version")
	}

	verbose, ok := get(1)
	if !ok {
		warn(1, "ufw status")
	}
	s.StatusVerbose = strings.TrimSpace(verbose)
	parseVerbose(s, verbose)

	if out, ok := get(5); ok {
		kv := parseShellVars(out)
		s.DefaultIncoming = policyName(kv["DEFAULT_INPUT_POLICY"])
		s.DefaultOutgoing = policyName(kv["DEFAULT_OUTPUT_POLICY"])
		s.DefaultRouted = policyName(kv["DEFAULT_FORWARD_POLICY"])
		s.DefaultApp = strings.ToLower(kv["DEFAULT_APPLICATION_POLICY"])
		s.IPv6 = strings.ToLower(kv["IPV6"])
	}
	if out, ok := get(6); ok {
		kv := parseShellVars(out)
		if lvl := strings.ToLower(kv["LOGLEVEL"]); lvl != "" {
			s.Logging = lvl
		}
	}

	numberedOut, _ := get(2)
	numbered := ParseNumbered(numberedOut)
	v4Out, v4ok := get(3)
	v6Out, v6ok := get(4)
	var v4, v6 []Tuple
	if v4ok {
		var errs []error
		v4, errs = ParseTuples(v4Out, false)
		for _, e := range errs {
			s.Warnings = append(s.Warnings, e.Error())
		}
		if v6ok {
			v6, errs = ParseTuples(v6Out, true)
			for _, e := range errs {
				s.Warnings = append(s.Warnings, e.Error())
			}
		}
		s.TuplesOK = len(errs) == 0
	} else {
		warn(3, "reading /etc/ufw/user.rules (rule moving/editing disabled)")
	}
	if s.TuplesOK && s.Active && len(numbered) != len(v4)+len(v6) {
		s.Warnings = append(s.Warnings, "rule files and 'ufw status numbered' disagree; showing rule files")
	}
	s.Rules = MergeRules(v4, v6, s.TuplesOK, numbered)

	if out, ok := get(7); ok {
		for _, name := range ParseAppList(out) {
			s.Apps = append(s.Apps, AppProfile{Name: name})
		}
	}
	if out, ok := get(8); ok {
		infos := ParseAppInfo(out)
		byName := map[string]AppProfile{}
		for _, a := range infos {
			byName[a.Name] = a
		}
		for i, a := range s.Apps {
			if info, ok := byName[a.Name]; ok {
				s.Apps[i] = info
			}
		}
	}
	return s
}

var defaultRe = regexp.MustCompile(`(\w+) \((incoming|outgoing|routed)\)`)

func parseVerbose(s *Snapshot, out string) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Status":
			s.Active = v == "active"
		case "Logging":
			if v == "off" {
				s.Logging = "off"
			} else if i, j := strings.Index(v, "("), strings.Index(v, ")"); i >= 0 && j > i {
				s.Logging = v[i+1 : j]
			} else {
				s.Logging = v
			}
		case "Default":
			for _, m := range defaultRe.FindAllStringSubmatch(v, -1) {
				switch m[2] {
				case "incoming":
					s.DefaultIncoming = m[1]
				case "outgoing":
					s.DefaultOutgoing = m[1]
				case "routed":
					if m[1] == "disabled" {
						s.RoutedNote = "routing disabled (net.ipv4.ip_forward=0)"
					} else {
						s.DefaultRouted = m[1]
					}
				}
			}
		case "New profiles":
			s.DefaultApp = v
		}
	}
}

func parseShellVars(content string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

func policyName(iptables string) string {
	switch strings.ToUpper(iptables) {
	case "ACCEPT":
		return "allow"
	case "DROP":
		return "deny"
	case "REJECT":
		return "reject"
	}
	return ""
}

// ParseAppList parses "ufw app list".
func ParseAppList(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  ") && strings.TrimSpace(line) != "" {
			names = append(names, strings.TrimSpace(line))
		}
	}
	return names
}

// ParseAppInfo parses "ufw app info NAME" or "ufw app info all".
func ParseAppInfo(out string) []AppProfile {
	var apps []AppProfile
	var cur *AppProfile
	section := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, " \r")
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Profile:"):
			apps = append(apps, AppProfile{Name: strings.TrimSpace(strings.TrimPrefix(line, "Profile:"))})
			cur = &apps[len(apps)-1]
			section = ""
		case cur == nil:
		case strings.HasPrefix(line, "Title:"):
			cur.Title = strings.TrimSpace(strings.TrimPrefix(line, "Title:"))
			section = ""
		case strings.HasPrefix(line, "Description:"):
			cur.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
			section = "desc"
		case strings.HasPrefix(line, "Port:") || strings.HasPrefix(line, "Ports:"):
			section = "ports"
		case trimmed == "" || trimmed == "--":
			if section == "desc" {
				section = ""
			}
		case section == "ports":
			cur.Ports = append(cur.Ports, trimmed)
		case section == "desc":
			cur.Description += " " + trimmed
		}
	}
	return apps
}

// ListeningEntry is one socket from "ufw show listening".
type ListeningEntry struct {
	Proto   string
	Port    string
	Address string
	Program string
	Rules   []string
}

var (
	listenHdrRe  = regexp.MustCompile(`^(\w+):$`)
	listenSockRe = regexp.MustCompile(`^  (\S+) (\S+)(?: \((.*)\))?$`)
	listenRuleRe = regexp.MustCompile(`^   (\[\s*\d+\].*)$`)
)

// ParseListening parses "ufw show listening".
func ParseListening(out string) []ListeningEntry {
	var entries []ListeningEntry
	proto := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, " \r")
		if m := listenHdrRe.FindStringSubmatch(line); m != nil {
			proto = m[1]
		} else if m := listenRuleRe.FindStringSubmatch(line); m != nil && len(entries) > 0 {
			e := &entries[len(entries)-1]
			e.Rules = append(e.Rules, m[1])
		} else if m := listenSockRe.FindStringSubmatch(line); m != nil && proto != "" {
			entries = append(entries, ListeningEntry{Proto: proto, Port: m[1], Address: m[2], Program: m[3]})
		}
	}
	return entries
}

// ParseAdded parses "ufw show added" into the ufw argument strings.
func ParseAdded(out string) []string {
	var cmds []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ufw ") {
			cmds = append(cmds, strings.TrimPrefix(line, "ufw "))
		}
	}
	return cmds
}
