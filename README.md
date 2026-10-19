# ufwgui

A graphical front end for the Uncomplicated Firewall (`ufw`), written in Go with [Fyne](https://fyne.io) (BSD-3-Clause).

## Layout

| Tab | ufw commands |
|---|---|
| **Status & Policies** | `enable`, `disable`, `reload`, `reset`, `default allow\|deny\|reject incoming\|outgoing\|routed`, `logging off\|on\|low\|medium\|high\|full`, `version`, `status verbose` |
| **Rules** | `status numbered`, simple and full rule syntax (`allow\|deny\|reject\|limit`, `route`, `in\|out on IFACE`, `log\|log-all`, `proto`, `from/to ADDR port\|app`, `comment`), `insert NUM`, `prepend`, `delete NUM`, `delete RULE`, `--dry-run`, plus edit and move |
| **Application Profiles** | `app list`, `app info`, `app update [--add-new] PROFILE\|all`, `app default allow\|deny\|reject\|skip`, quick `allow\|deny\|reject\|limit PROFILE` |
| **Reports** | `show raw\|builtins\|before-rules\|user-rules\|after-rules\|logging-rules\|listening\|added`, `status [verbose\|numbered]` |
| **Command Log** | every command run in this session, with its output (in memory only) |
| **Settings** | ufw path and privilege escalation method |

Click any column header in a list to sort by it. Clicking again reverses the order, and a third click restores the original order.

### Reordering rules

ufw has no move command. The Rules tab moves a rule (Top / Up / Down / Bottom / Move to…) or edits it in three steps, run in one elevated shell:

1. `ufw --force delete N`
2. `ufw insert M <rule>`, or append when M is the last position in its block
3. only if step 2 failed: re-add the original rule at N

The rule's exact definition is read from `/etc/ufw/user.rules` and `user6.rules`. ufw always lists IPv4 rules before IPv6 rules, so a rule can only be moved within its own IP family. Manual moving is available only while the list is shown in rule order (not sorted by a column).

## Build (Ubuntu)

```sh
sudo apt install golang gcc libgl1-mesa-dev xorg-dev   # Fyne build dependencies
go build -o ufwgui .
./ufwgui
```

Requires Go ≥ 1.27.2. If the installed Go is older, `go build` downloads the required toolchain automatically (unless `GOTOOLCHAIN=local` is set).

## Privileges

ufw needs root. Choose how commands are elevated in **Settings**:

- **pkexec** (default): a polkit password prompt. Each action, including a refresh, prompts at most once.
- **sudo -n**: requires a `NOPASSWD` sudoers entry for ufw, cat and sh.
- **none**: when the program itself runs as root. This is selected automatically when it does.

## Privacy

The program makes no network connections and sends no telemetry. Settings are stored locally through Fyne's preferences.

## Tests

```sh
go test ./...
```

Tests cover the parsers, the rule move/replace command sequences, and a headless UI smoke test.
