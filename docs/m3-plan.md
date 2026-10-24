# M3 plan: dangerous modules and the dead-man switch (v0.3.0)

M3 adds the modules that can lock someone out (`user.admin`, `ssh.server`, `firewall.inbound`), one that can annoy them (`ssh.bruteforce`), the dead-man switch and `confirm` that make the first three safe, the `minimal` and `web` profiles, and the `sshd-config` crate. It builds on the M2 engine as it is (see [the M2 plan](m2-plan.md)) and is the subset of [the architecture](architecture.md) these modules need; the rest waits (see [Deferred](#deferred-from-the-architecture)).

Debian 12/13 and Ubuntu 22.04/24.04 with systemd only, as in M2.

## Decisions

### Modules

| Module | Changes | Fixes | Dead-man |
|---|---|---|---|
| `user.admin` | a login user (created or existing), its `~/.ssh/authorized_keys`, `/etc/sudoers.d/90-vps-ready-admin` | none (a precondition for `ssh.server`) | yes: the confirm is "Challenge 1" |
| `ssh.server` | `/etc/ssh/sshd_config.d/00-vps-ready.conf`; reloads sshd | `SSH-001` to `SSH-007` | yes |
| `firewall.inbound` | installs `nftables` if missing; `/etc/vps-ready/firewall.nft`, `/etc/systemd/system/vps-ready-firewall.service`, which it enables and starts | `FW-001` | yes |
| `ssh.bruteforce` | installs `fail2ban` and `python3-systemd`; `/etc/fail2ban/jail.d/90-vps-ready.local`; enables and starts `fail2ban` | `SSH-008` (new) | no |

The registry order is `user.admin`, `ssh.server`, `firewall.inbound`, `ssh.bruteforce`, `kernel.sysctl`, `updates.auto`. A fixed order is enough: the only dependency (`ssh.server` needs a working admin) is a plan-time check, not an ordering problem, so there is still no `requires` or topological sort.

**One apply, one transaction, one confirm.** If an apply contains several dead-man modules, they share a transaction and a single confirm from a new session proves all of them together (the new login uses the new user, the new sshd config and the new firewall). If the confirm never comes, everything reverts. Step by step (`--module user.admin` first, then the rest) stays possible for those who want to see which part fails.

**`user.admin` details:**
- Params: `name` (default `admin`), `authorized_keys` (a list of public key lines), `sudo = "nopasswd" | "password"` (default `nopasswd`).
- If `authorized_keys` is empty, it copies the keys of the user who ran `sudo` (`SUDO_USER`, else root): they just logged in with one of them. Lines with options (`command=`, `no-pty`, ...) are skipped with a note. Ubuntu and AWS images put `command="echo 'Please login as the user ...'"` on root's keys, which would make the new account unusable.
- A missing user is created with `useradd --create-home --user-group --shell /bin/bash --password '*'`. `*` (no password, not locked) rather than `!`, since sshd without PAM refuses a locked account even for key logins. An existing user is used as is; the module never changes its password or shell.
- **Gotcha 5 (passwordless admin, password sudo, root disabled).** Decided: there is no special sudo rule for `confirm`; the confirm itself is `sudo vps-ready confirm`, so it proves login, key and sudo in one step, which is what Challenge 1 is for.
  - `sudo = "nopasswd"` writes `<name> ALL=(ALL:ALL) NOPASSWD: ALL` to `/etc/sudoers.d/90-vps-ready-admin` (mode `0440`, validated with `visudo -cf` on `files/<n>.after`). This is what cloud images already do for their default user. The file name has no `.`, because sudo skips files in an include directory whose name contains a `.` or ends in `~`.
  - `sudo = "password"` adds the user to the `sudo` group and is refused at plan time unless the account already has a usable password hash in `/etc/shadow` ("set one with `passwd <name>` first"). vps-ready never takes a password.
  - Rejected: a `NOPASSWD` rule scoped to `vps-ready confirm`. It would let Challenge 1 pass while the admin's general sudo is broken, which is exactly the lockout the challenge exists to catch. Also rejected: taking the code through a root-owned FIFO or socket. It needs a listener running for the whole window, peer authentication (`SO_PEERCRED` plus the same process-tree walk), and it would not prove sudo either.
- Reversibility: `partial`. A created user is removed with `userdel` but its home directory stays (it may hold files the admin made during the window). Groups it added to an existing user are removed with `gpasswd -d`.

**`ssh.server` details:**
- One drop-in, `/etc/ssh/sshd_config.d/00-vps-ready.conf` (D5). sshd uses the first value it reads for each keyword and expands `Include` globs in lexical order (both from `sshd_config(5)`), so `00-` wins over cloud-init's `50-cloud-init.conf` (`PasswordAuthentication yes`) and over anything later in `sshd_config`.
- It manages exactly the keywords of `SSH-001` to `SSH-007`: `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `HostbasedAuthentication no`, `PermitUserEnvironment no`. As in `kernel.sysctl`, a keyword goes into the drop-in only if its effective value fails the control or the drop-in already lists it.
- It never writes `Port`, `ListenAddress`, `AllowGroups`, `AuthenticationMethods` or crypto lists. Port 22 stays (D6), which also keeps `ssh.socket` out of scope: on Ubuntu 22.10+ the listening port comes from the socket unit, and changing it needs `daemon-reload` and a socket restart. A unit test enforces the list.
- Plan-time checks (read-only):
  - `/etc/ssh/sshd_config` has an `Include` that covers `/etc/ssh/sshd_config.d/*.conf` before any `Match` block and before any line that sets one of the managed keywords. Debian and Ubuntu ship it as the first directive. If it is missing, the module is not applicable (it does not edit the main file, D5; adding the line is M6 work for Alpine). The `sshd-config` crate answers this.
  - **Lockout invariant:** disabling root or password login needs a non-root user with a non-empty `authorized_keys` and sudo rights: the admin of this plan, or `SUDO_USER`. Otherwise the plan refuses. This only stops an apply that could never be confirmed; the confirm is the real proof.
- Validate in two steps: `sshd -t -f files/<n>.after` checks the drop-in's own syntax before anything is written; after writing, `sshd -t` checks the whole config before the reload. A failure at either step rolls back without reloading.
- Reload, not restart: `systemctl try-reload-or-restart ssh.service`. Existing sessions survive a reload (sshd re-executes the listener on `SIGHUP`; sessions are separate processes). With socket activation and no running `ssh.service`, it does nothing, and the next connection starts sshd with the new config.
- Verify: `sshd -T -C user=<admin>,host=<client ip>,addr=<client ip>` shows every managed keyword at its value. The `-C` form also applies `Match` blocks for the admin's own connection.
- No `/etc/cloud/cloud.cfg.d/99-vps-ready.cfg` (`ssh_pwauth: false`): cloud-init only writes `50-cloud-init.conf`, which `00-` already beats. If a VM test ever shows cloud-init writing elsewhere, it comes back.

**`firewall.inbound` details:**
- **nftables directly, not ufw.** Decided because:
  - one backend for Debian (no ufw by default) and Ubuntu;
  - the whole ruleset is one file that `nft -c -f` validates and `nft -f` loads atomically;
  - vps-ready owns one table, `inet vps_ready`, so rollback deletes that table and nothing else: Docker's chains, fail2ban's `f2b-table` and any rules of the admin stay untouched (gotcha 8, "a firewall reset wipes Docker chains");
  - ufw's state is several files plus `ufw enable`, and `ufw reset` rewrites its chains.
  - Cost: `ufw status` does not show our rules. The plan says so.
- **Not applicable** when ufw or firewalld is active (that firewall is already managed; vps-ready leaves it alone and `FW-001` reports it), when the iptables-legacy `filter` table is loaded (facts already detect it; those rules cannot be read), or when `nft list tables` fails (unprivileged LXC).
- Not `nftables.service`: Debian's `/etc/nftables.conf` starts with `flush ruleset`, so `systemctl restart nftables` would wipe Docker's rules. Our own unit `vps-ready-firewall.service` is `Type=oneshot`, `RemainAfterExit=yes`, `ExecStart`/`ExecReload=nft -f /etc/vps-ready/firewall.nft`, `ExecStop=nft delete table inet vps_ready`, ordered `Before=network-pre.target`. The file replaces only our table (`table inet vps_ready {}` then `delete table inet vps_ready` then the definition, in one atomic load).
- The ruleset (askama template, pinned by `insta`):

```
table inet vps_ready {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif lo accept
    meta l4proto icmp accept
    meta l4proto ipv6-icmp accept            # neighbor discovery, path MTU: never block ICMPv6
    ip6 saddr fe80::/10 udp dport 546 accept # DHCPv6 client
    tcp dport { 22, 80, 443 } accept         # profile `allow` plus every current SSH port
    udp dport { 443 } accept
  }
}
```

- **Never cut the current SSH port.** The accepted TCP ports always include the port of the applying session, every port sshd listens on (facts) and `port` from `sshd -T`, whatever the profile says. A unit test renders the ruleset for hosts with different SSH ports and checks this on the rendered model. Verify reads back `nft -j list table inet vps_ready` and checks the ports again.
- `ct state established` keeps the open session through the load: conntrack already tracks it, or picks it up mid-stream.
- **Docker:** the table filters only the `input` hook. Traffic to a published port is DNATed and goes through `forward`, so this module neither breaks Docker nor fixes `FW-002`; the plan prints the published ports from facts with the `FW-002` advice. When Docker is present, input from `docker0` and `br-*` is accepted, so containers that reach host services keep working (ufw's default breaks this). `FW-002` waits for `deploy.docker` (M5).
- Other base chains on the input hook (ufw inactive leftovers, an admin's own table) still apply: in nftables a packet must be accepted by every base chain on a hook. The plan lists them.
- Outbound is not filtered, so cloud metadata (169.254.169.254) stays reachable.

**`ssh.bruteforce` details** (open question 2: fail2ban by default, CrowdSec later):
- Only in the `web` profile. Once SSH is key-only, brute force is mostly log noise, and OpenSSH 9.8+ has `PerSourcePenalties` on by default (Debian 13 has it; Debian 12 and Ubuntu 22.04/24.04 do not).
- Packages `fail2ban` and `python3-systemd` (Debian 12+ has no `auth.log` by default, so the jail reads the journal).
- The drop-in sets `[DEFAULT] backend = systemd`, `banaction = nftables-multiport`, `banaction_allports = nftables-allports`, and `[sshd] enabled = true` with `ignoreip = 127.0.0.1/8 ::1 <admin ip>`. `jail.d/*.local` is read after `jail.d/*.conf`, so it wins over Debian's `defaults-debian.conf`.
- fail2ban's own table (`inet f2b-table`, input hook, priority -1) coexists with ours: a drop in any base chain is final.
- Validate with `fail2ban-client -t` after writing; then `systemctl restart fail2ban` (it is not on the SSH path, so restart is fine).
- New control `SSH-008` (low): "Repeated failed logins are slowed down", a new check kind `ssh_rate_limited`: passes if `sshd -T` shows `persourcepenalties` other than `no`, or `fail2ban-client status sshd` succeeds. `fix = "ssh.bruteforce"`.

### Resources

M3 adds three kinds to the closed enum. `Reversibility` stays `Reversible | Partial`; nothing in M3 is irreversible.

```rust
pub enum Resource {
    File(File), Sysctl(Sysctl), Package(Package),        // M2, unchanged
    Service(Service),        // systemd unit: enabled: bool, active: bool
    User(User),              // name, groups to add; created with useradd if missing
    AuthorizedKeys(AuthorizedKeys), // user, key lines that must be present
}

pub enum Backup {
    // M2 variants unchanged
    Service { unit: String, was_enabled: bool, was_active: bool },
    User { name: String, created: bool, added_groups: Vec<String> },
    AuthorizedKeys { user: String, path: PathBuf, n: u32, original: Option<FileCopy>, created_dir: bool },
}
```

- **`Service`**: state from `systemctl show -p UnitFileState,ActiveState` (the facts helper). `apply` runs `systemctl daemon-reload` first (a unit file may be new in the same transaction), then `enable`/`start` as needed. A masked unit is refused at plan time. Restore stops and disables what was off. `Reversible`.
- **`User`**: `Partial` (see `user.admin`). Restore of a created user runs `userdel`, which fails while the user has processes; that is a rollback that did not complete (exit 3), with `pkill -u <name>; userdel <name>` as the by-hand step.
- **`AuthorizedKeys`**: the path comes from the passwd entry at apply time, since the user may not exist at plan time (which is why this is not a `File`: a `File` refuses a missing parent and needs its owner up front). It creates `~/.ssh` (`0700`) and the file (`0600`) owned by the user, only adds missing lines, and never removes one. The before and after bytes use `files/<n>` like `File`. Every path component is checked with `lstat`; a symlink is refused. `Reversible`.
- **No `FirewallRuleset`.** The firewall is two `File`s and a `Service`; loading, reloading and deleting the table are the unit's `ExecStart`, `ExecReload` and `ExecStop`. Restore runs in reverse journal order, so the service stops (deleting the table) while its unit file still exists.
- The sudoers file is a `File` with `Validate { program: "visudo", args: ["-cf"] }`.

### Module trait (M3)

```rust
pub trait Module {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn why(&self) -> &'static str;
    fn needs_deadman(&self) -> bool { false }            // new
    fn applicable(&self, facts: &Facts) -> Applicability;
    fn notes(&self, facts: &Facts) -> Vec<String>;
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError>;  // was (facts, sys) -> Vec<Resource>
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> { Ok(()) }     // new: sshd -T -C, nft list table
}
pub struct PlanCx<'a> { pub facts: &'a Facts, pub params: &'a toml::Table, pub session: Option<&'a Session> }
pub struct ModuleSteps { pub resources: Vec<Resource>, pub reloads: Vec<Reload> }
pub struct Reload { pub check: Option<Cmd>, pub run: Cmd }   // e.g. check `sshd -t`, run `systemctl try-reload-or-restart ssh.service`
```

- Each module parses its own `params` into a `#[serde(deny_unknown_fields)]` struct, so a typo in a profile is an error that names the module.
- Reloads run after all resources of the module are applied, before verify; each is journaled (`reloaded`). On rollback, a module whose reload was journaled is reloaded again after its resources are restored. A failed `check` is an apply failure; the reload is not run.
- Verify is the M2 generic check (every `diff()` is `None`) plus `Module::verify`.

### Profiles

TOML (D4), strict, embedded with `include_str!`:

```toml
# profiles/minimal.toml
schema = 1
[modules."user.admin"]
[modules."ssh.server"]
[modules."firewall.inbound"]
allow = ["22/tcp"]
[modules."kernel.sysctl"]
[modules."updates.auto"]
```

`web.toml` is `minimal` plus `allow = ["22/tcp", "80/tcp", "443/tcp", "443/udp"]` and `[modules."ssh.bruteforce"]`.

- `--profile minimal|web|<path>`. A user file can set `extends = "minimal"` or `"web"` (built-in names only, one level), then override per-module fields, or drop a module with `enabled = false`. Tables merge one level deep; lists replace.
- A typical user file only sets the admin:

```toml
schema = 1
extends = "web"
[modules."user.admin"]
name = "deploy"
authorized_keys = ["ssh-ed25519 AAAAC3Nza... me@laptop"]
```

- **Without `--profile` or `--module`, `plan` and `apply` select only `kernel.sysctl` and `updates.auto`**, as in v0.2. The dead-man modules and `ssh.bruteforce` (which installs packages) need a profile or `--module`. So `sudo vps-ready apply --yes` from v0.2 does not start locking down SSH after an upgrade. `audit` prints `fix: sudo vps-ready apply --module ssh.server` as today.
- No `/etc/vps-ready/config.toml` and no JSON Schema yet (see Deferred).

### Dead-man switch

**Arming before the change.** The architecture's diagram arms after `Applied`; that leaves a crash between the change and the arm with nothing to revert it. M3 arms first:

```
lock; refuse if any transaction is unfinished or pending-confirm
plan, prompt, re-diff (as M2)
create txn; journal "begin"
if a module needs the dead-man:
    enable vps-ready-deadman.service (boot hook, below)
    systemd-run --unit=vps-ready-deadman-<txn> --on-active=<window + 10 min> \
        --timer-property=AccuracySec=1s \
        /usr/local/bin/vps-ready rollback --txn <txn> --deadman
    journal "armed" {unit, boot_id, deadline}
backup / apply each resource (as M2)
reload each module (check, then run); journal "reloaded"
verify; on failure roll back (stopping the timer) as M2
dead-man: re-arm the timer to <window> from now; journal "state pending-confirm" {deadline, live_since, session}
          release the lock; wait (below)
no dead-man: journal "state applied"
```

The extra 10 minutes on the first arm cover the apply itself (a package install can take minutes); the window the user sees starts when the changes are live.

**Surviving the apply process and the SSH session.** A transient systemd timer: `systemd-run` hands the timer and its service to PID 1, outside the user's session scope, so it fires when the apply process, its terminal and its SSH connection are all gone (including with logind's `KillUserProcesses=yes`). Rejected: a double-forked detached process, which a session teardown or the OOM killer can take with it, and which a reboot loses anyway. Without systemd the dead-man modules are not applicable in M3 (the OpenRC watchdog is M6).

**Reboot during the window.** Transient units live in `/run` and vanish at reboot, so arming also enables a static unit, `vps-ready-deadman.service` (`Type=oneshot`, `After=local-fs.target`, `WantedBy=multi-user.target`, `ExecStart=vps-ready rollback --deadman-boot`). At boot it rolls back any transaction that is pending-confirm, or unfinished with an `armed` record, whose `boot_id` is not the current boot, with reason `deadman-reboot`. It is disabled again when the transaction is confirmed or rolled back. A reboot is treated as "not confirmed": the user may have rebooted because they were locked out.

**The dead-man rollback entry point** (`--deadman`, hidden from help) differs from a manual rollback in two ways: it waits up to 60 s for the lock instead of failing at once (a `confirm` may hold it for a moment), and it re-reads the journal under the lock: if the transaction is already confirmed or rolled back, it exits 0; if the deadline was extended, it re-arms and exits 0.

**Deadlines** are kept as `CLOCK_BOOTTIME` seconds plus `boot_id` (with wall-clock time for display), so an NTP step during the window cannot shorten or lengthen it. The timer uses `--on-active` (monotonic) as well.

**Defaults:** a 5-minute window (the architecture's 180 s is short for opening a terminal, finding the key and typing a command). `apply --deadman <dur>` sets it, from `1m` to `30m`. `confirm --extend [<dur>]` (default `5m`) moves the deadline to now plus the duration, at most 30 minutes ahead; it works from any session, including the old one, since extending proves nothing. Each extend re-arms the timer and journals `extended`.

**What `apply` prints and does while pending:**

```
Changes are live. Open a NEW terminal and run:

    ssh -p 22 admin@203.0.113.10 sudo vps-ready confirm

If no new session confirms by 14:07:30 UTC (4:59 left), every change is rolled back.
More time: sudo vps-ready confirm --extend
```

- The user, address and port are real values: the admin of this plan (else `SUDO_USER`), and the server address and port of the applying session. Behind NAT (cloud floating IPs) that is the private address; the line then adds "(or the address you connected to)". No network call is made to find a public IP.
- `apply` then waits with a countdown (one line on a TTY, one line per minute otherwise) until the transaction leaves pending-confirm: confirmed exits 0, rolled back by the dead-man exits 1. Ctrl-C stops waiting, not the timer, and exits 4 (new: "pending; the changes revert at <time> unless confirmed").
- `history` shows a pending transaction as `pending-confirm (reverts in 3m12s)`. There is no separate `status` command.

**`confirm`:**

```
vps-ready confirm [--txn ID] [--extend [DUR]]
```

- No code. At most one transaction can be pending (apply refuses otherwise), so a code would only disambiguate between one choice. The protection is the new-session check, not a secret: a code printed in the old terminal proves nothing about the new one. `--txn` is for scripts that want to be explicit.
- Needs root. Exit 0 confirmed (or extended), 2 on any refusal: nothing pending, deadline passed, same session, no SSH session found.
- On success: takes the lock, re-checks the state and deadline, stops the timer (`systemctl stop vps-ready-deadman-<txn>.timer`), disables the boot hook, journals `confirmed` {session, user} and `state confirmed`.

**What "new session" means** (design flag 1). `SSH_CONNECTION` is not usable: sudo's `env_reset` (on by default) keeps only `TERM`, `PATH`, `HOME`, `MAIL`, `SHELL`, `LOGNAME`, `USER` and `SUDO_*`, and Debian and Ubuntu add no `env_keep` for it. Users are never asked for `--preserve-env`, and the current notice in `facts::session` that suggests it goes away.
- **Detection:** as root, walk `/proc/self` up through `PPid` (at most 64 steps, through the `sudo` monitor process `use_pty` adds) to the nearest ancestor whose `comm` is `sshd` or `sshd-session` (OpenSSH 9.8 split the per-session code into `sshd-session`). That process is the session. Its identity is its PID plus its start time (field 22 of `/proc/<pid>/stat`), so PID reuse cannot fake a match. `SSH_CONNECTION` is read from the `environ` of its child in the chain (the login shell, or the command of `ssh host cmd`), and the login user from that child's uid.
- **A session counts as new when** it is a different sshd session from the one recorded at apply **and** it started after `live_since`, the moment the changes went live. The second rule matters: a second terminal opened before apply also survives the sshd reload and the firewall's `established` rule, so it proves nothing.
- For a transaction with `user.admin`, the confirming user must be that admin.
- No sshd ancestor (console, tmux, screen): `confirm` refuses with "run it from a new SSH login". An `apply` with no sshd ancestor records no session; then any SSH session that started after `live_since` confirms.
- Not used: `loginctl` and utmp (an extra source to parse for the same answer; utmp has no entry for `ssh host cmd`), and `/proc/self/sessionid` (needs kernel audit support).

**Prior art** (iptables-apply, `netplan try`, Junos `commit confirmed`) confirms from the same session, or from any session. That catches a change that kills the connection, but not the common SSH and firewall lockout where the open connection survives (sshd reload, conntrack) and new ones fail. Requiring a new login is the point of D7, at the cost of one extra terminal.

### Engine changes

**Transaction states:**

```rust
pub enum TxnState {
    Planned,
    Applied,
    PendingConfirm { deadline: Deadline, live_since: u64, session: Option<SessionId> }, // new
    Confirmed,                                                                       // new
    RolledBack { reason: RollbackReason },
}
pub enum RollbackReason { ApplyFailed, VerifyFailed, Manual, DeadmanTimeout, DeadmanReboot } // last two new
pub struct SessionId { pid: u32, start: u64 }      // Copy, like the rest of TxnState
```

The architecture's `code: String` is dropped (see `confirm`), which keeps `TxnState` `Copy`.

New transitions (everything else stays an error, through the one `(state, event)` match):
- `Planned` + `armed` | `reloaded` → `Planned`;
- `Planned` + `state pending-confirm` → `PendingConfirm`;
- `PendingConfirm` + `extended` → `PendingConfirm` (with the new deadline); + `confirmed` → `PendingConfirm`; + `state confirmed` → `Confirmed`;
- `PendingConfirm` + `rollback` (deadman-timeout, deadman-reboot or manual), then `restored`/`reloaded`, then `state rolled-back`;
- `Confirmed` behaves like `Applied`: a manual rollback is allowed.

**New journal events:**

```json
{"at":1792932000,"event":"armed","unit":"vps-ready-deadman-20261025T120000Z","boot_id":"0d5c...","deadline":{"boottime":1234,"wall":1792932900}}
{"at":1792932040,"event":"reloaded","unit":"ssh.service"}
{"at":1792932041,"event":"state","state":"pending-confirm","deadline":{"boottime":1575,"wall":1792932341},"live_since":1275,"session":{"pid":812,"start":10433}}
{"at":1792932100,"event":"extended","deadline":{"boottime":1934,"wall":1792932700}}
{"at":1792932130,"event":"confirmed","session":{"pid":951,"start":12655},"user":"admin","client":"198.51.100.7"}
{"at":1792932130,"event":"state","state":"confirmed"}
```

- A pending-confirm transaction is finished in the M2 sense (its last line is a `state` record), but `apply` also refuses while one exists, and `rollback --last` picks it first.
- The state directory, lock, IDs, atomic writes and the safety check are unchanged. A dead-man rollback refused by the safety check (someone changed a managed file during the window) restores nothing, as in M2; the refusal goes to the unit's log, the boot hook stays enabled, and `history` shows it.

**Exit codes** (additions in bold):

| Code | `apply` | `confirm` |
|---|---|---|
| 0 | applied, nothing to do, **or confirmed while waiting** | confirmed or extended |
| 1 | failed and rolled back, **or rolled back by the dead-man while waiting** | |
| 2 | error | refused or error |
| 3 | rollback did not complete | |
| **4** | **stopped waiting; still pending** | |

### `sshd-config` crate

`crates/sshd-config`, a workspace member with no dependency on the app:
- `effective::parse`: the `sshd -T` parser that is in `facts/ssh.rs` today (`SshdConfig`), moved as is.
- `files`: a small reader for `sshd_config` and its `Include`s (keywords, quoted arguments, `Include` globs in lexical order, `Match` boundaries). It answers two questions: does an `Include` cover a directory before a given keyword or `Match`, and which file sets a keyword first. The second explains a failing control in `audit` ("set by /etc/ssh/sshd_config.d/50-cloud-init.conf").
- Not a full linter, no rendering, no crypto checks. Property tests (any input, no panic) instead of fuzzing for now. `publish = false` until the API settles (see Deferred).

### Known limits

- The printed `ssh` line has the private address on NATed hosts.
- `Match` blocks for other users or addresses are not checked; verify covers the admin's own connection only.
- Other input base chains still filter; Docker's published ports bypass the input chain (`FW-002`), including with Docker's own nftables backend.
- A user who reconnects through a jump host or mosh still has an sshd ancestor; tmux, screen and the console do not.
- `userdel` fails while the admin has processes (exit 3, with the by-hand step).
- Dead-man modules need systemd.

## Testing

**Layer 1:**
- Per module: `insta` snapshots of the plan and of every rendered file (drop-in, ruleset, unit, jail, sudoers); apply → next plan empty; apply → rollback → the tempdir tree equals the original.
- `ssh.server`: never `Port`, `ListenAddress`, `AllowGroups`; refuses without a keyed sudo user; the `Include` check on fixtures (missing, after a `Match`, after a conflicting line).
- `firewall.inbound`: the SSH ports are always accepted, for random port sets (proptest); not applicable with ufw active, firewalld active or legacy tables. Audit and fix agree: `FW-001` passes on the `nft -j` output of the loaded table (a fixture captured in the VM test).
- `user.admin`: option-prefixed keys skipped; `password` refused without a hash; sudoers file name has no `.`.
- Engine: the new transitions; arm before the first change; a crash after `armed` at every journal line (the dead-man entry point and the boot hook both finish the rollback); confirm racing the timer under the lock; extend re-arms.
- Session detection on a fake `/proc`: `sudo` with and without `use_pty`, `sshd` and `sshd-session` names, no sshd ancestor, PID reuse with a different start time, a session that started before `live_since`.
- `sshd-config`: parser property tests and include-order fixtures.

**Layer 2 (containers):** `ssh.bruteforce` full cycle (packages, jail, service; `SSH-008` passes; rollback). `user.admin` create and rollback. nftables syntax and load/delete in the container's own network namespace.

**Layer 3 (VMs): extend the existing QEMU/KVM harness; no Incus.** The milestone named Incus before `test/vm-cycle.sh` existed. QEMU with KVM already boots the four official cloud images on stock GitHub runners; Incus would add an install step, an image server and a second way to run the same VMs. What Incus would add, a command channel that does not depend on SSH, the dead-man tests do not need: a locked-out VM gets its SSH back when the timer fires, and the serial console log is already captured. The milestone description changes to "VM tests (QEMU/KVM)". New cycles, all with `--deadman 1m`:
1. `minimal` profile → confirm from a second SSH session as the admin → `SSH-001` to `SSH-007` and `FW-001` pass; root and password logins are refused; port 80 (forwarded to the host) times out.
2. Apply and do not confirm → within deadline + 10 s, the drop-in, the table and the user are gone and the old login works.
3. Apply, reboot during the window → after boot, rolled back with `deadman-reboot`.
4. `confirm` from the applying session and from a session opened before apply are refused.
5. Ubuntu 24.04 (`ssh.socket`): the reload applies the drop-in to new connections.
The seed adds a key for root so test 1 can try a root login. QEMU's user network makes every connection come from 10.0.2.2, which is fine: sessions differ by sshd process, not by address.

## PR sequence

Each PR leaves `main` releasable. Dangerous modules are registered only once the dead-man exists.

1. **`docs: plan M3`** (this document).

2. **`refactor: sshd-config crate`**: move the `sshd -T` parser; add the file reader. Tests: property tests, include fixtures. *Parallel with 3, 4, 5.*

3. **`feat(facts): SSH session from the process tree`**: `Session` with `SessionId`, client and server address, login user; drop the `--preserve-env` notice; `detect` shows it. Tests: fake `/proc` cases above. *Parallel.*

4. **`feat(resource): Service, User and AuthorizedKeys`**: the three kinds, their backups and restores. Tests: `FakeRunner` argv; round trips on a tempdir; symlinked `~/.ssh` refused. *Parallel.*

5. **`feat(engine): reloads, module verify and params`**: the new `Module` signature, `ModuleSteps`, `Reload`, `reloaded` events, rollback reloads; existing modules move over unchanged in behavior. *Parallel.*

6. **`feat(engine): dead-man switch and confirm`** (needs 3, 5): states, events, arming, `systemd-run`, the boot hook, the `--deadman` and `--deadman-boot` entry points, `confirm`, `apply --deadman`, the countdown, exit 4, `history` remaining time; the VM harness gains a second SSH session and a root key. A test-only dead-man module exercises it. Tests: engine and session tests above; VM cycles 2 to 4 with the test module.

7. **`feat(config): minimal and web profiles`** (needs 5): profile parsing, `extends`, `--profile`, the default selection without dead-man modules. *Parallel with 6.*

8. **`feat(modules): user.admin`** (needs 4, 6, 7). Layer 2 cycle.

9. **`feat(modules): ssh.server`** (needs 2, 6; `askama` arrives here): `fix` on `SSH-001` to `SSH-007`. VM cycles 1 and 5. *Parallel with 8 and 10.*

10. **`feat(modules): firewall.inbound`** (needs 4, 6, 7): `fix` on `FW-001`. VM cycle 1 (firewall part). *Parallel with 8 and 9.*

11. **`feat(modules): ssh.bruteforce`** (needs 4, 7): `SSH-008` and its check kind; layer 2 cycle. *Parallel with 8 to 10.*

12. **`chore: release v0.3.0`**: README, `architecture.md` (arm before change, no confirm code, `TxnState`), `decisions.md` (open question 2 decided), `testing.md`, `security-baseline.md` (5-minute window), milestone description, version bump.

Waves: {2, 3, 4, 5} → {6, 7} → {8, 9, 10, 11} → 12.

## Deferred from the architecture

| Architecture | M3 | When |
|---|---|---|
| Changing the SSH port, `ssh.socket` edits, SELinux port labels | Port 22 stays (D6) | Only if asked for; Tailscale is the real fix (M5) |
| `AllowGroups`, `MaxAuthTries`, `LoginGraceTime`, `LogLevel VERBOSE`, crypto subtraction, FIDO2/TOTP | The seven keywords of `SSH-001` to `SSH-007` | Paranoid profile (M6), each with a control |
| `/etc/cloud/cloud.cfg.d/99-vps-ready.cfg` | Not needed: `00-` wins | If a test shows otherwise |
| ufw and firewalld backends; the `Firewall`, `Sshd`, `ServiceManager`, `PkgManager` platform traits | nftables and systemd called directly; Debian family only | M6 (RHEL, Alpine) |
| OpenRC watchdog, firewalld runtime-only rules | Dead-man modules need systemd | M6 |
| `--deadman=off` and `--deadman=selftest` (cloud-init) | Every dead-man apply waits for a confirm | M5, with `export cloud-init` |
| Confirm codes | No code; one pending transaction at a time | If more than one can ever be pending |
| Fixing `FW-002` (`daemon.json` `ip`, `DOCKER-USER`) | Reported in the plan | `deploy.docker` (M5) |
| CrowdSec | fail2ban | M6, opt-in |
| `paranoid` profile, JSON Schema (`schemars`), `/etc/vps-ready/config.toml`, multi-level `extends` | `minimal`, `web`, one-level `extends` from built-ins | JSON Schema with the wizard (M4); `config.toml` with `drift` (M6) |
| `requires`/`conflicts` and a topological sort | Fixed registry order and a plan-time check | When a module order cannot be fixed |
| `FirewallRuleset`, `LineInFile`, `Command` resources | `File` + `Service` | If a module cannot do without them |
| Publishing `sshd-config` to crates.io; `cargo-fuzz` targets | Workspace crate, property tests | After v0.3.0, once its API settles |
| Incus VM tests | Existing QEMU/KVM harness | Not planned |
| Tailscale and closing public 22 | Not in M3 | M5 |

## Open for the owner

1. One transaction and one confirm for `user.admin` + `ssh.server` + `firewall.inbound`, rather than three challenges.
2. Plain `apply` (no `--profile`, no `--module`) leaves the dead-man modules out.
3. No confirm code.
4. `sudo = "nopasswd"` as the default; `password` only for accounts that already have one.
5. nftables in our own table and unit on Ubuntu too, and not applicable when ufw is active.
6. A 5-minute default window, `1m` to `30m`, and exit code 4 for "still pending".
7. Accept input from `docker0` and `br-*` when Docker is present.
8. Drop "Incus" from the milestone in favor of the existing QEMU harness.
