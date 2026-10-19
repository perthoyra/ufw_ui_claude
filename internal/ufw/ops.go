package ufw

import (
	"errors"
	"strconv"
)

// Values accepted by ufw commands.
var (
	Actions         = []string{"allow", "deny", "reject", "limit"}
	Policies        = []string{"allow", "deny", "reject"}
	PolicyDirs      = []string{"incoming", "outgoing", "routed"}
	AppPolicies     = []string{"allow", "deny", "reject", "skip"}
	LogLevels       = []string{"off", "on", "low", "medium", "high", "full"}
	RuleLogOptions  = []string{"", "log", "log-all"}
	Protocols       = []string{"any", "tcp", "udp", "ah", "esp", "gre", "ipv6", "igmp"}
	Reports         = []string{"raw", "builtins", "before-rules", "user-rules", "after-rules", "logging-rules", "listening", "added"}
)

// ErrNotMovable explains why a rule cannot be moved.
var ErrNotMovable = errors.New("rule cannot be moved")

// StepsDeleteNumber deletes rule n without prompting.
func StepsDeleteNumber(n int) []Step {
	return []Step{Ufw(true, "--force", "delete", strconv.Itoa(n))}
}

// familyBounds returns the first and last global rule numbers of the family of
// rule n (ufw numbers all IPv4 rules first, then all IPv6 rules).
func familyBounds(rules []Rule, n int) (int, int) {
	v6 := rules[n-1].V6
	first, last := 0, 0
	for _, r := range rules {
		if r.V6 == v6 {
			if first == 0 {
				first = r.Number
			}
			last = r.Number
		}
	}
	return first, last
}

// placeSteps adds args at global position pos of a family whose last position
// (after one rule of that family was removed) is lastAfterDelete+1. Inserting
// past the last rule is not allowed by ufw, so that case appends.
func placeStep(args []string, pos, familyLast int, cond *Cond) Step {
	var s Step
	if pos >= familyLast {
		s = Ufw(true, args...)
	} else {
		s = Ufw(true, append([]string{"insert", strconv.Itoa(pos)}, args...)...)
	}
	s.RunIf = cond
	return s
}

// StepsReplace replaces rule n with a rule built from newArgs, keeping its
// position. If adding the new rule fails, the original rule is restored.
func StepsReplace(rules []Rule, n int, newArgs []string) ([]Step, error) {
	return stepsMoveReplace(rules, n, n, newArgs)
}

// StepsMove moves rule from to position to (both global rule numbers in the
// same IP family), implemented as delete followed by insert because ufw has
// no move command. If the insert fails the rule is restored where it was.
func StepsMove(rules []Rule, from, to int) ([]Step, error) {
	return stepsMoveReplace(rules, from, to, nil)
}

func stepsMoveReplace(rules []Rule, from, to int, newArgs []string) ([]Step, error) {
	if from < 1 || from > len(rules) {
		return nil, ErrNotMovable
	}
	r := rules[from-1]
	if r.Tuple == nil {
		return nil, errors.New("rule details unavailable (could not read /etc/ufw/user*.rules)")
	}
	first, last := familyBounds(rules, from)
	if to < first || to > last {
		return nil, errors.New("rules can only be moved within their IP family (IPv4 rules are always listed before IPv6 rules)")
	}
	orig := r.Tuple.Args()
	if newArgs == nil {
		newArgs = orig
	}
	steps := StepsDeleteNumber(from)
	steps = append(steps, placeStep(newArgs, to, last, &Cond{Step: 0, OK: true}))
	steps = append(steps, placeStep(orig, from, last, &Cond{Step: 1, OK: false}))
	return steps, nil
}

// SnapshotSteps returns the commands that collect the full firewall state.
func SnapshotSteps() []Step {
	return []Step{
		Ufw(false, "version"),
		Ufw(false, "status", "verbose"),
		Ufw(false, "status", "numbered"),
		{Prog: "cat", Args: []string{"/etc/ufw/user.rules"}},
		{Prog: "cat", Args: []string{"/etc/ufw/user6.rules"}},
		{Prog: "cat", Args: []string{"/etc/default/ufw"}},
		{Prog: "cat", Args: []string{"/etc/ufw/ufw.conf"}},
		Ufw(false, "app", "list"),
		Ufw(false, "app", "info", "all"),
	}
}
