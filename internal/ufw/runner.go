// Package ufw wraps the ufw command line tool: it runs ufw (with privilege
// escalation when needed), and parses its output and rule files.
package ufw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Privilege selects how commands are elevated to root.
type Privilege string

const (
	PrivNone   Privilege = "none"   // the GUI itself runs as root
	PrivPkexec Privilege = "pkexec" // polkit graphical authentication
	PrivSudo   Privilege = "sudo"   // sudo -n (requires NOPASSWD or a cached ticket)
)

// Privileges lists the supported elevation methods.
var Privileges = []Privilege{PrivPkexec, PrivSudo, PrivNone}

// Cond makes a Step conditional on the outcome of an earlier step.
type Cond struct {
	Step int  // index of the earlier step in the same Run call
	OK   bool // true: run only if that step succeeded; false: only if it ran and failed
}

// Step is one command executed as part of a Run call.
type Step struct {
	Prog     string   // program to run; empty means ufw
	Args     []string // arguments
	Mutating bool     // true if the command changes firewall state (honours dry-run)
	RunIf    *Cond    // nil means always run
}

// Ufw returns a step running ufw with args.
func Ufw(mutating bool, args ...string) Step {
	return Step{Args: args, Mutating: mutating}
}

// Result is the outcome of one Step.
type Result struct {
	Command  string
	Output   string
	ExitCode int
	Skipped  bool
}

// OK reports whether the step ran and exited with status 0.
func (r Result) OK() bool { return !r.Skipped && r.ExitCode == 0 }

// LogEntry records one Run call for the command log.
type LogEntry struct {
	Time    time.Time
	Label   string
	Results []Result
	Err     error
}

// Runner executes ufw commands. All steps of a Run call are executed inside a
// single elevated shell so the user authenticates at most once per action.
type Runner struct {
	mu        sync.Mutex
	UfwPath   string
	Privilege Privilege
	DryRun    bool
	OnLog     func(LogEntry)
}

// NewRunner returns a runner with sensible defaults.
func NewRunner() *Runner {
	return &Runner{UfwPath: "/usr/sbin/ufw", Privilege: PrivPkexec}
}

// ErrAuth is returned when privilege escalation failed or was cancelled.
var ErrAuth = errors.New("authentication failed or was cancelled")

// Run executes steps in order in one privileged shell.
func (r *Runner) Run(ctx context.Context, label string, steps ...Step) ([]Result, error) {
	r.mu.Lock()
	ufwPath, priv, dry := r.UfwPath, r.Privilege, r.DryRun
	r.mu.Unlock()

	nonce := newNonce()
	script, display := buildScript(nonce, ufwPath, dry, steps)

	argv := []string{"/bin/sh", "-c", script}
	switch priv {
	case PrivPkexec:
		argv = append([]string{"pkexec"}, argv...)
	case PrivSudo:
		argv = append([]string{"sudo", "-n"}, argv...)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	results := parseScriptOutput(nonce, string(out), display)

	var runErr error
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// The script always exits 0, so a non-zero status comes from the
			// elevation wrapper (pkexec: 126 dismissed, 127 not authorised).
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = ee.Error()
			}
			runErr = fmt.Errorf("%w: %s", ErrAuth, msg)
		} else {
			runErr = err
		}
	}

	if r.OnLog != nil {
		r.OnLog(LogEntry{Time: time.Now(), Label: label, Results: results, Err: runErr})
	}
	return results, runErr
}

// SetConfig updates runner settings safely.
func (r *Runner) SetConfig(ufwPath string, priv Privilege, dry bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.UfwPath, r.Privilege, r.DryRun = ufwPath, priv, dry
}

// IsDryRun reports whether dry-run mode is on.
func (r *Runner) IsDryRun() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.DryRun
}

func newNonce() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// ShellQuote quotes s for POSIX sh.
func ShellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:,=@%+", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CommandString renders a step as a human readable command line.
func CommandString(prog string, args []string) string {
	parts := []string{ShellQuote(prog)}
	for _, a := range args {
		parts = append(parts, ShellQuote(a))
	}
	return strings.Join(parts, " ")
}

func stepArgv(ufwPath string, dry bool, s Step) (string, []string) {
	if s.Prog != "" {
		return s.Prog, s.Args
	}
	args := s.Args
	if dry && s.Mutating {
		args = append([]string{"--dry-run"}, args...)
	}
	return ufwPath, args
}

func buildScript(nonce, ufwPath string, dry bool, steps []Step) (string, []string) {
	var b strings.Builder
	display := make([]string, len(steps))
	b.WriteString("export LC_ALL=C LANG=C LANGUAGE=\n")
	b.WriteString("PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n")
	for i := range steps {
		fmt.Fprintf(&b, "r_%d=s\n", i)
	}
	for i, s := range steps {
		prog, args := stepArgv(ufwPath, dry, s)
		if s.Prog == "" {
			display[i] = CommandString("ufw", args)
		} else {
			display[i] = CommandString(prog, args)
		}
		cond := "true"
		if s.RunIf != nil {
			if s.RunIf.OK {
				cond = fmt.Sprintf(`[ "$r_%d" = 0 ]`, s.RunIf.Step)
			} else {
				cond = fmt.Sprintf(`[ "$r_%d" != s ] && [ "$r_%d" != 0 ]`, s.RunIf.Step, s.RunIf.Step)
			}
		}
		fmt.Fprintf(&b, "if %s; then\n", cond)
		fmt.Fprintf(&b, "printf '\\n@@%s:BEGIN:%d@@\\n'\n", nonce, i)
		fmt.Fprintf(&b, "%s </dev/null 2>&1\n", CommandString(prog, args))
		fmt.Fprintf(&b, "r_%d=$?\n", i)
		fmt.Fprintf(&b, "printf '\\n@@%s:END:%d:%%s@@\\n' \"$r_%d\"\n", nonce, i, i)
		b.WriteString("fi\n")
	}
	b.WriteString("exit 0\n")
	return b.String(), display
}

func parseScriptOutput(nonce, out string, display []string) []Result {
	results := make([]Result, len(display))
	for i := range display {
		results[i] = Result{Command: display[i], Skipped: true, ExitCode: -1}
		begin := fmt.Sprintf("\n@@%s:BEGIN:%d@@\n", nonce, i)
		endPrefix := fmt.Sprintf("\n@@%s:END:%d:", nonce, i)
		bi := strings.Index(out, begin)
		if bi < 0 {
			continue
		}
		rest := out[bi+len(begin):]
		ei := strings.Index(rest, endPrefix)
		if ei < 0 {
			results[i].Skipped = false
			results[i].Output = rest
			continue
		}
		tail := rest[ei+len(endPrefix):]
		code := -1
		if j := strings.Index(tail, "@@"); j >= 0 {
			if c, err := strconv.Atoi(tail[:j]); err == nil {
				code = c
			}
		}
		results[i].Skipped = false
		results[i].Output = rest[:ei]
		results[i].ExitCode = code
	}
	return results
}
