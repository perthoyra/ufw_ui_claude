// Package ufw wraps the ufw command line tool: it runs ufw (with privilege
// escalation when needed), and parses its output and rule files.
package ufw

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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

// Runner executes ufw commands. All steps of a Run call are compiled into one
// script. With privilege escalation the scripts are executed by a long-lived
// elevated helper shell, so the user authenticates once, when the first
// command runs, rather than once per action.
type Runner struct {
	mu        sync.Mutex
	UfwPath   string
	Privilege Privilege
	DryRun    bool
	OnLog     func(LogEntry)

	sess   *session   // elevated helper; guarded by mu
	execMu sync.Mutex // serialises requests to sess
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

	var out string
	var runErr error
	if priv == PrivNone {
		b, err := exec.CommandContext(ctx, "/bin/sh", "-c", script).CombinedOutput()
		out = string(b)
		if err != nil {
			runErr = execError(err, out)
		}
	} else {
		out, runErr = r.runElevated(ctx, priv, nonce, script)
	}
	results := parseScriptOutput(nonce, out, display)

	if r.OnLog != nil {
		r.OnLog(LogEntry{Time: time.Now(), Label: label, Results: results, Err: runErr})
	}
	return results, runErr
}

// execError converts a failed process into an error. The script always exits
// 0, so a non-zero status comes from the elevation wrapper (pkexec: 126
// dismissed, 127 not authorised) and is reported as ErrAuth.
func execError(err error, out string) error {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return err
	}
	msg := strings.TrimSpace(out)
	if msg == "" {
		msg = ee.Error()
	}
	return fmt.Errorf("%w: %s", ErrAuth, msg)
}

// runElevated executes script in the elevated helper, starting it (and
// prompting for credentials) if it is not running or the privilege changed.
func (r *Runner) runElevated(ctx context.Context, priv Privilege, nonce, script string) (string, error) {
	r.execMu.Lock()
	defer r.execMu.Unlock()

	r.mu.Lock()
	if r.sess != nil && r.sess.priv != priv {
		r.sess.close()
		r.sess = nil
	}
	if r.sess == nil {
		s, err := startSession(priv)
		if err != nil {
			r.mu.Unlock()
			return "", err
		}
		r.sess = s
	}
	s := r.sess
	r.mu.Unlock()

	out, err := s.exec(ctx, nonce, script)
	if err != nil {
		r.mu.Lock()
		if r.sess == s {
			r.sess = nil
		}
		r.mu.Unlock()
	}
	return out, err
}

// Close stops the elevated helper shell, if any.
func (r *Runner) Close() {
	r.mu.Lock()
	s := r.sess
	r.sess = nil
	r.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// helperScript runs as root for the lifetime of a session. It reads requests
// of the form "<line count> <nonce>\n<script lines>" from stdin, runs each
// script in a child shell and ends its output with a DONE marker. It exits
// when stdin is closed, i.e. when the GUI exits.
const helperScript = `PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
while read -r n t; do
	s=
	while [ "$n" -gt 0 ] && IFS= read -r l; do
		s="$s$l
"
		n=$((n - 1))
	done
	/bin/sh -c "$s" </dev/null 2>&1
	printf '\n@@%s:DONE@@\n' "$t"
done
`

// session is a running elevated helper shell.
type session struct {
	priv      Privilege
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	out       *os.File
	rd        *bufio.Reader
	closeOnce sync.Once
}

func startSession(priv Privilege) (*session, error) {
	argv := []string{"/bin/sh", "-c", helperScript}
	switch priv {
	case PrivPkexec:
		argv = append([]string{"pkexec"}, argv...)
	case PrivSudo:
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	err = cmd.Start()
	pw.Close()
	if err != nil {
		stdin.Close()
		pr.Close()
		return nil, err
	}
	return &session{priv: priv, cmd: cmd, stdin: stdin, out: pr, rd: bufio.NewReader(pr)}, nil
}

// exec sends script to the helper and returns its output up to the DONE
// marker. On any failure the session is closed and must not be reused.
func (s *session) exec(ctx context.Context, nonce, script string) (string, error) {
	stop := context.AfterFunc(ctx, s.close)
	defer stop()

	if !strings.HasSuffix(script, "\n") {
		script += "\n"
	}
	var out strings.Builder
	_, err := fmt.Fprintf(s.stdin, "%d %s\n%s", strings.Count(script, "\n"), nonce, script)
	done := "@@" + nonce + ":DONE@@"
	for err == nil {
		var line string
		line, err = s.rd.ReadString('\n')
		if strings.TrimSuffix(line, "\n") == done {
			return out.String(), nil
		}
		out.WriteString(line)
	}

	s.close()
	if ctx.Err() != nil {
		return out.String(), ctx.Err()
	}
	// The helper exited before finishing: either elevation failed or was
	// cancelled (pkexec/sudo print the reason), or the helper was killed.
	msg := strings.TrimSpace(out.String())
	if msg == "" {
		msg = "the elevated helper exited"
	}
	return out.String(), fmt.Errorf("%w: %s", ErrAuth, msg)
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		s.stdin.Close()
		s.out.Close()
		_ = s.cmd.Process.Kill() // fails once elevated; closing stdin ends the helper
		go s.cmd.Wait()
	})
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
