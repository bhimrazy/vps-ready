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
| `ssh.bruteforce` | installs `nftables`, `python3-systemd` and `fail2ban`; `/etc/fail2ban/jail.d/90-vps-ready.local`; enables and starts `fail2ban` | `SSH-008` (new) | no |

The registry order is `user.admin`, `ssh.server`, `firewall.inbound`, `ssh.bruteforce`, `kernel.sysctl`, `updates.auto`. A fixed order is enough: the only dependency (`ssh.server` needs a working admin) is a plan-time check, not an ordering problem, so there is still no `requires` or topological sort.

**One apply, one transaction, one confirm.** If an apply contains several dead-man modules, they share a transaction and a single confirm from a new session proves all of them together (the new login uses the new user, the new sshd config and the new firewall). If the confirm never comes, everything reverts. Step by step (`--module user.admin` first, then the rest) stays possible for those who want to see which part fails.

**`user.admin` details:**
- Params: `name` (default `admin`), `authorized_keys` (a list of public key lines), `sudo = "nopasswd" | "password"` (default `nopasswd`, used only for a user this module creates; see below).
- If `authorized_keys` is empty, it copies the keys of the user who ran `sudo` (`SUDO_USER`, else root): they just logged in with one of them. Lines with options (`command=`, `no-pty`, ...) are skipped with a note. Ubuntu and AWS images put `command="echo 'Please login as the user ...'"` on root's keys, which would make the new account unusable.
- A missing user is created with `useradd --create-home --user-group --shell /bin/bash`, which leaves the password field locked (`!`): no password login and no `su`. With `UsePAM yes` (the Debian and Ubuntu default) a locked password does not stop key logins (checked on Debian 13 and Ubuntu 24.04). With `UsePAM no`, sshd refuses key logins to a `!` account, so the module reads `usepam` from `sshd -T`: when it is `no`, the user is created with `--password '*'` (no password, not locked) and the plan says so ("UsePAM is off: password set to `*` so key logins work"). An existing user's password field is never touched. The flip side: locking an account does not keep it out of SSH; only its `authorized_keys` (or `AllowUsers`/`DenyUsers`) does. Rollback therefore relies on `userdel` and the `AuthorizedKeys` restore, never on locking.
- **An existing user keeps its sudo.** If `sudo -l -U <name>` lists rules, the module writes no sudoers file and adds no group, whatever `sudo` says; the plan notes it. Only an existing user without sudo, or a created one, gets the `sudo` param applied.
- **Gotcha 5 (passwordless admin, password sudo, root disabled).** Decided: there is no special sudo rule for `confirm`; the confirm itself is `sudo vps-ready confirm`, so it proves login, key and sudo in one step, which is what Challenge 1 is for.
  - `sudo = "nopasswd"` writes `<name> ALL=(ALL:ALL) NOPASSWD: ALL` to `/etc/sudoers.d/90-vps-ready-admin` (mode `0440`, validated with `visudo -cf` on `files/<n>.after`). This is what cloud images already do for their default user. The file name has no `.`, because sudo skips files in an include directory whose name contains a `.` or ends in `~`.
  - `sudo = "password"` adds the user to the `sudo` group and is refused at plan time unless the account already has a usable password hash in `/etc/shadow` ("set one with `passwd <name>` first"). vps-ready never takes a password.
  - Rejected: a `NOPASSWD` rule scoped to `vps-ready confirm`. It would let Challenge 1 pass while the admin's general sudo is broken, which is exactly the lockout the challenge exists to catch. Also rejected: taking the code through a root-owned FIFO or socket. It needs a listener running for the whole window, peer authentication (`SO_PEERCRED` plus the same process-tree walk), and it would not prove sudo either.
- Reversibility: `partial`. A created user is removed with `userdel` but its home directory stays (it may hold files the admin made during the window). Groups it added to an existing user are removed with `gpasswd -d`. The user is the first resource applied, so it is the last restored: when `userdel` fails (the admin still has processes), the drop-in and the firewall are already back, and only the account is left.

**`ssh.server` details:**
- One drop-in, `/etc/ssh/sshd_config.d/00-vps-ready.conf` (D5). sshd uses the first value it reads for each keyword and expands `Include` globs in lexical order (both from `sshd_config(5)`), so `00-` wins over cloud-init's `50-cloud-init.conf` (`PasswordAuthentication yes`) and over anything later in `sshd_config`.
- It manages exactly the keywords of `SSH-001` to `SSH-007`: `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `HostbasedAuthentication no`, `PermitUserEnvironment no`. As in `kernel.sysctl`, a keyword goes into the drop-in only if its effective value fails the control or the drop-in already lists it.
- It never writes `Port`, `ListenAddress`, `AllowGroups`, `AuthenticationMethods` or crypto lists. Port 22 stays (D6), which also keeps `ssh.socket` out of scope: on Ubuntu 22.10+ the listening port comes from the socket unit, and changing it needs `daemon-reload` and a socket restart. A unit test enforces the list.
- Plan-time checks (read-only):
  - `/etc/ssh/sshd_config` has an `Include` that covers `/etc/ssh/sshd_config.d/*.conf` before any `Match` block and before any line that sets one of the managed keywords. Debian and Ubuntu ship it as the first directive. If it is missing, the module is not applicable (it does not edit the main file, D5; adding the line is M6 work for Alpine). The `sshd-config` crate answers this.
  - **Lockout invariant:** disabling root or password login needs a non-root user with a non-empty `authorized_keys` and sudo rights: the admin of this plan, or `SUDO_USER`. Otherwise the plan refuses. This only stops an apply that could never be confirmed; the confirm is the real proof.
- Validate in two steps: `sshd -t -f files/<n>.after` checks the drop-in's own syntax before anything is written; after writing, `sshd -t` checks the whole config before the reload. A failure at either step rolls back without reloading.
- Reload, not restart: `systemctl try-reload-or-restart ssh.service`. Existing sessions survive a reload (sshd re-executes the listener on `SIGHUP`; sessions are separate processes). On Ubuntu 24.04, `ssh.socket` is enabled with `Accept=no` and `ssh.service` shows "disabled" yet runs once a connection arrived; `systemctl reload ssh.service` keeps its main PID, and the unit's `ExecReload` runs `sshd -t` before the `HUP` (checked on Ubuntu 24.04). With no running `ssh.service`, the reload does nothing, and the next connection starts sshd with the new config.
- The SSH port facts add `systemctl show ssh.socket -p Listen`, so a socket-activated port that `sshd -T` does not show still counts as a current SSH port (for the firewall).
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
- `nft` is not on Debian 13's cloud image (the `nftables` package is missing) and is on Ubuntu 24.04's, so the module plans a `Package` for it when missing. `iptables` is `iptables-nft` on both, which is why the facts already see ufw and Docker rules in the nftables ruleset.
- Not `nftables.service`: `/etc/nftables.conf` starts with `flush ruleset` on Debian 13 and Ubuntu 24.04, so `systemctl restart nftables` would wipe Docker's rules and ours. The service ships disabled on both, but an admin may enable it, so:
  - our unit is ordered `After=nftables.service`, so a boot that loads `/etc/nftables.conf` loads ours after its flush;
  - the plan notes when `nftables.service` is enabled ("restarting it removes the vps-ready table until `systemctl restart vps-ready-firewall`").
- Our own unit `vps-ready-firewall.service` is `Type=oneshot`, `RemainAfterExit=yes`, `ExecStart`/`ExecReload=nft -f /etc/vps-ready/firewall.nft`, `ExecStop=-nft delete table inet vps_ready` (the `-` ignores a table someone already flushed), with `DefaultDependencies=no`, ordered `Before=network-pre.target shutdown.target` with `Conflicts=shutdown.target`. The file replaces only our table (`table inet vps_ready {}` then `delete table inet vps_ready` then the definition, in one atomic load).
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
    udp sport 67 udp dport 68 accept         # DHCPv4 replies that conntrack does not match (broadcast)
    ip6 saddr fe80::/10 udp dport 546 accept # DHCPv6 client
    tcp dport { 22, 80, 443 } accept         # profile `allow` plus every current SSH port
    udp dport { 443 } accept
  }
}
```

- **Never cut the current SSH port.** The accepted TCP ports always include the port of the applying session, every port sshd listens on (facts, including `ssh.socket`'s `Listen`) and `port` from `sshd -T`, whatever the profile says. A unit test renders the ruleset for hosts with different SSH ports and checks this on the rendered model. Verify reads back `nft -j list table inet vps_ready` and checks the ports again.
- Why the port rule and not only `ct state established`: in a VM test, loading this table kept the live session, but a flow that predates conntrack and has no accept rule for its port can be dropped (checked on Debian 13 and Ubuntu 24.04). Always accepting the current SSH ports is what protects the open session; `established` covers everything else.
- **Docker:** the table filters only the `input` hook. Traffic to a published port is DNATed and goes through `forward`, so this module neither breaks Docker nor fixes `FW-002`; the plan prints the published ports from facts with the `FW-002` advice. When Docker is present, input from `docker0` and `br-*` is accepted, so containers that reach host services keep working (ufw's default breaks this). The cost: a compromised container can reach every host service, the same as with no firewall; the plan says so when it adds the rule. `FW-002` waits for `deploy.docker` (M5).
- Other base chains on the input hook (ufw inactive leftovers, an admin's own table) still apply: in nftables a packet must be accepted by every base chain on a hook. The plan lists them.
- Outbound is not filtered, so cloud metadata (169.254.169.254) stays reachable.

**`ssh.bruteforce` details** (open question 2: fail2ban by default, CrowdSec later):
- Only in the `web` profile. Once SSH is key-only, brute force is mostly log noise, and OpenSSH 9.8+ has `PerSourcePenalties` on by default (Debian 13 has it; Debian 12 and Ubuntu 22.04/24.04 do not).
- Packages `nftables`, `python3-systemd` and `fail2ban` (Debian 12+ has no `auth.log` by default, so the jail reads the journal; `nft` is missing on Debian 13's cloud image, and fail2ban only recommends `nftables`, which `--no-install-recommends` skips).
- The packaged `defaults-debian.conf` already sets `banaction = nftables` and `backend = systemd` (Debian 13 under `[sshd]`, Ubuntu 24.04 under `[DEFAULT]`). The drop-in sets them again under `[DEFAULT]` (harmless where they match, and needed on Debian 12, whose file sets only `[sshd] enabled = true`), plus `[sshd] enabled = true` with `ignoreip = 127.0.0.1/8 ::1 <admin ip>`. `jail.d/*.local` is read after `jail.d/*.conf`, so it wins.
- fail2ban's own table (`inet f2b-table`, input hook, priority `filter - 1`, created on the first ban) coexists with ours: a drop in any base chain is final.
- Validate with `fail2ban-client -t` after writing (exits 0 on a good config on Debian 13 and Ubuntu 24.04); then `systemctl try-restart fail2ban` (it is not on the SSH path, so restart is fine; `try-` because the rollback replay runs after the `Service` restore, and must not start a fail2ban that restore stopped).
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

The safety check (`unchanged`) and the by-hand step (`by_hand`) for the new kinds:

| Backup | Unchanged when | By hand |
|---|---|---|
| `Service` | enabled and active are each the applied or the original value | `systemctl disable --now <unit>` (or `enable --now`) |
| `User` (created) | the account exists with the uid apply gave it, or is already gone | `pkill -u <name>; userdel <name>` |
| `User` (groups added) | the user's groups contain the added ones, or none of them | `gpasswd -d <name> <group>` for each |
| `AuthorizedKeys` | the file equals `.after` or `.before` (absent counts as `.before` if it did not exist) | copy `files/<n>.before` to the path, or remove it |
- **No `FirewallRuleset`.** The firewall is two `File`s and a `Service`; loading, reloading and deleting the table are the unit's `ExecStart`, `ExecReload` and `ExecStop`. Restore runs in reverse journal order, so the service stops (deleting the table) while its unit file still exists.
- The sudoers file is a `File` with `Validate { program: "visudo", args: ["-cf"] }`.

### Module trait (M3)

```rust
pub trait Module {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn why(&self) -> &'static str;
    fn needs_deadman(&self) -> bool { false }            // new
    fn force_restore(&self) -> bool { false }            // new: the dead-man restores its resources even if changed
    fn applicable(&self, facts: &Facts) -> Applicability;
    fn notes(&self, facts: &Facts) -> Vec<String>;
    fn plan(&self, cx: &PlanCx, sys: Sys) -> Result<ModuleSteps, ModuleError>;  // was (facts, sys) -> Vec<Resource>
    fn verify(&self, cx: &PlanCx, sys: Sys) -> Result<(), String> { Ok(()) }     // new: sshd -T -C, nft list table
}
pub struct PlanCx<'a> { pub facts: &'a Facts, pub params: &'a toml::Table, pub session: Option<&'a Session> }
pub struct ModuleSteps { pub resources: Vec<Resource>, pub reloads: Vec<Reload> }

#[derive(Serialize, Deserialize)]            // journaled, so a later process can replay it
#[serde(rename_all = "kebab-case")]
pub enum Reload {
    SshdReload,       // check `sshd -t`, then `systemctl try-reload-or-restart ssh.service`
    FirewallReload,   // check `nft -c -f /etc/vps-ready/firewall.nft`, then `systemctl try-reload-or-restart vps-ready-firewall.service`
    Fail2banRestart,  // check `fail2ban-client -t`, then `systemctl try-restart fail2ban.service`
    DaemonReload,     // `systemctl daemon-reload`, no check
}
```

- `Reload` is a closed enum, like `Resource`, rather than a pair of `Cmd`s: the journal records which reload ran (`reloaded {"reload":"sshd-reload"}`), and a rollback in a later process, perhaps a newer binary, runs the same reload from that name alone. Each variant has a fixed check and a fixed command.
- Each module parses its own `params` into a `#[serde(deny_unknown_fields)]` struct, so a typo in a profile is an error that names the module.
- Reloads run after all resources of the module are applied, before verify; each is journaled. A failed check is an apply failure; the reload is not run.
- On rollback, a reload that was journaled runs again after the module's resources are restored, **check first**. If the check fails (for example the admin broke `sshd_config` during the window), the reload is skipped and logged, and the running listener keeps its config instead of dying on a bad one.
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
    check the binary path (below); install and enable the boot hook (below)
    systemd-run --unit=vps-ready-deadman-<txn>-1 --on-active=<first deadline> \
        --timer-property=AccuracySec=1s \
        <binary> rollback --txn <txn> --deadman
    journal "armed" {unit, boot_id, deadline}
    a failed systemd-run disables the boot hook again and ends the transaction here
    (state rolled-back, apply-failed), before any backup
backup / apply each resource (as M2; each "backup" record also carries force_restore, below)
reload each module (check, then run); journal "reloaded"
verify; on failure roll back (stopping the timer) as M2
dead-man: re-arm to <window> from now; journal "state pending-confirm" {deadline, unit, live_since, session}
          release the lock; wait (below)
no dead-man: journal "state applied"
```

**The first deadline** is the window plus the sum of the command timeouts of every step in the plan (each `Package` step has `APT_TIMEOUT`, 600 s; reloads and validates have their own), so the timer cannot fire while apply is still within its own limits. The window the user sees starts when the changes are live. If the timer still fires mid-apply (a hung step), the `--deadman` entry point waits for the lock; once apply has died or finished, it sees the result and acts on it (below).

**Re-arming.** `systemd-run --unit` fails if a unit of that name exists, so every re-arm (at pending-confirm, on each `extend`) first stops the old timer and its service, then starts `vps-ready-deadman-<txn>-<n+1>`, and journals the new unit name in `state pending-confirm` or `extended`. `confirm` and the manual rollback stop the unit the journal names last.

**The binary path** passed to `systemd-run` and written into the boot hook is `std::env::current_exe()`, checked first: it and every parent directory must be owned by root and not writable by group or others, and it must not be under `/home`, `/tmp`, `/var/tmp` or `/dev/shm`. Otherwise the dead-man modules refuse to apply ("install vps-ready to /usr/local/bin first"). A root timer that runs a file a user can replace would be a root shell for that user.

**Surviving the apply process and the SSH session.** A transient systemd timer: `systemd-run` hands the timer and its service to PID 1, outside the user's session scope, so it fires when the apply process, its terminal and its SSH connection are all gone (including with logind's `KillUserProcesses=yes`). Rejected: a double-forked detached process, which a session teardown or the OOM killer can take with it, and which a reboot loses anyway. Without systemd the dead-man modules are not applicable in M3 (the OpenRC watchdog is M6).

**Reboot during the window.** Transient units live in `/run` and vanish at reboot, so the engine also keeps one unit file of its own, `/etc/systemd/system/vps-ready-deadman.service`:

```ini
[Unit]
Description=vps-ready: roll back an unconfirmed change after a reboot
DefaultDependencies=no
After=local-fs.target vps-ready-firewall.service
Before=ssh.service ssh.socket shutdown.target
Conflicts=shutdown.target
[Service]
Type=oneshot
TimeoutStartSec=120
ExecStart=<binary> rollback --deadman-boot
[Install]
WantedBy=multi-user.target
```

- It is engine infrastructure, not a resource: written outside any transaction (atomic write, before the first arm), never rolled back, and left in place afterwards. Arming enables it; confirm and every rollback of the transaction disable it, so it only runs at a boot that follows an unconfirmed apply.
- `DefaultDependencies=no` is required: the default `After=basic.target` comes after `sockets.target`, so with `Before=ssh.socket` it would be an ordering cycle that systemd breaks by dropping a unit. `vps-ready-firewall.service` uses `DefaultDependencies=no` too, as `nftables.service` does, with `Before=shutdown.target` and `Conflicts=shutdown.target`.
- Only the edges it needs, because every extra edge is a chance for a cycle, and a cycle is a lockout: systemd breaks it by dropping a unit, which may be `ssh.socket` or the hook. `After=network-pre.target` and `Before=sockets.target` were in an earlier draft and form a cycle on a host with firewalld (`Before=network-pre.target`, `After=dbus.service`, which comes after `basic.target` and so after `sockets.target`). Both edges are redundant: `vps-ready-firewall.service` already orders the hook after the firewall, and `Before=ssh.socket` already orders it before sshd. VM cycle 4 runs `systemd-analyze verify` on both units.
- `TimeoutStartSec=120`: a oneshot defaults to no start timeout, and the hook is ordered before sshd, so a hung rollback would keep sshd from ever starting. `--deadman-boot` also bounds every subprocess it runs with a timeout, as the engine already does. If the hook times out, sshd starts anyway, and the transaction stays pending for a manual `rollback --last` from the console or the old config.
- Ordering: after our firewall loads and before sshd starts, so the boot rolls back the firewall table and the drop-in before the first login, and sshd starts with the restored config (no reload needed).
- It rolls back any transaction that is pending-confirm, or unfinished with an `armed` record, whose `boot_id` is not the current boot, with reason `deadman-reboot`. A reboot is treated as "not confirmed": the user may have rebooted because they were locked out.

**The dead-man rollback** (`--deadman` and `--deadman-boot`, hidden from help) differs from a manual rollback:
- **Lock:** it waits for the lock with no timeout instead of failing at once, since giving up would leave the lockout in place. Whoever holds the lock (an apply still running, a `confirm`) releases it within its own command timeouts or by dying.
- **Re-read under the lock:** if the transaction is already confirmed or rolled back, it exits 0; if the deadline was extended, it re-arms and exits 0.
- **Per resource, not all or nothing.** M2's safety check refuses the whole rollback if any resource changed since apply. For a manual rollback that is right; for the dead-man it means "the admin edited `00-vps-ready.conf` during the window, the deadline passed, nothing reverted, locked out". So in the dead-man paths:
  - resources of `ssh.server` and `firewall.inbound` are always restored, changed or not. They are unconfirmed by definition, and leaving them is the lockout. The current bytes of a changed file are first copied to `files/<n>.during`, so the edit is not lost, and the output names that file. That copy is best effort: if it fails (a full disk), the failure is logged and the restore goes ahead;
  - which resources these are comes from the journal, not from paths in the code: the `backup` record gains `force_restore: bool` (default `false` when absent, so M2 journals still read), set at apply time from a new `Module::force_restore()` (default `false`; `true` for `ssh.server` and `firewall.inbound`). It is not simply `needs_deadman()`: `user.admin` needs the dead-man too, but leaving an added key or account in place is not a lockout;
  - any other resource that fails the check (`user.admin`'s keys with a key the admin added, a service someone stopped) is skipped and journaled as `skipped {resource, by_hand}`; every resource that passes is restored;
  - `history` and the unit's log list what was skipped and the by-hand steps.
- **Restore first, journal best effort** (a full disk is one way the window can go wrong). The `rollback` record is attempted; if it cannot be written, the restores still run, each `restored` append is attempted, and the failure goes to stderr (the unit's log). Restoring a resource that is already at its `.before` state does nothing harmful, so the boot hook or a rerun converges once there is space.
- When resuming a transaction with no `rollback` record, the reason is `deadman-timeout` if its deadline has passed, `deadman-reboot` if its boot is gone, and `manual` only otherwise; the M2 "no record means manual" rule never relabels a dead-man rollback.

**Deadlines** are kept as `CLOCK_BOOTTIME` seconds plus `boot_id` (with wall-clock time for display), so an NTP step during the window cannot shorten or lengthen it. The timer uses `--on-active` (monotonic) as well.

**Defaults:** a 5-minute window (the architecture's 180 s is short for opening a terminal, finding the key and typing a command). `apply --deadman <dur>` sets it, from `1m` to `30m`. `confirm --extend [<dur>]` (default `5m`) moves the deadline to now plus the duration, at most 30 minutes ahead and at most 2 hours after `live_since` in total; it works from any session, including the old one, since extending proves nothing.

**What `apply` prints and does while pending:**

```
Changes are live. Open a NEW terminal and run:

    ssh -t -o ControlPath=none -p 22 admin@203.0.113.10 sudo vps-ready confirm

If no new session confirms by 14:07:30 UTC (4:59 left), every change is rolled back.
More time: sudo vps-ready confirm --extend
Do not edit files vps-ready manages until you confirm: an unconfirmed change reverts them.
```

- The user, address and port are real values: the admin of this plan (else `SUDO_USER`), and the server address and port of the applying session. Behind NAT (cloud floating IPs) that is the private address; the line then adds "(or the address you connected to)". No network call is made to find a public IP.
- `-o ControlPath=none` stops an `ssh` with `ControlMaster` in its config from reusing the old connection (a multiplexed session is a channel of the old sshd session, so `confirm` would refuse it). `-t` gives sudo a terminal if it asks for a password.
- `apply` then waits with a countdown (one line on a TTY, one line per minute otherwise) until the transaction leaves pending-confirm: confirmed exits 0, rolled back by the dead-man exits 1. Ctrl-C while waiting stops waiting, not the timer, and exits 4 (new: "pending; the changes revert at <time> unless confirmed").
- Ctrl-C (or a dropped session) **before** pending kills apply part way. The transaction is then unfinished with an `armed` record, and the first-arm timer rolls it back at its deadline; `sudo vps-ready rollback --last` does it sooner.
- `Progress` gains `Armed { deadline }`, `Reload(Reload)` and `Waiting { left }` for the CLI to show. The `Armed` line shows the first deadline ("Armed the dead-man switch: changes revert by 14:21:30 UTC if apply does not finish"), so a user whose apply dies knows when the host comes back.
- `history` shows a pending transaction as `pending-confirm (reverts in 3m12s)`. There is no separate `status` command.
- A manual `rollback` of a pending transaction stops its timer and disables the boot hook, like `confirm`.

**`confirm`:**

```
vps-ready confirm [--txn ID] [--extend [DUR]]
```

- No code. At most one transaction can be pending (apply refuses otherwise), so a code would only disambiguate between one choice. The protection is the new-session check, not a secret: a code printed in the old terminal proves nothing about the new one. `--txn` is for scripts that want to be explicit.
- Needs root. Exit 0 confirmed (or extended), 2 on any refusal: nothing pending, deadline passed, same session, no SSH session found.
- On success: takes the lock (waiting up to 10 s, since the dead-man entry point may hold it briefly), re-checks the state and deadline, stops the timer the journal names, disables the boot hook, journals `confirmed` {session, user} and `state confirmed`.

**What "new session" means** (design flag 1). `SSH_CONNECTION` is not usable: sudo's `env_reset` (on by default) keeps only `TERM`, `PATH`, `HOME`, `MAIL`, `SHELL`, `LOGNAME`, `USER` and `SUDO_*`, and the shipped `/etc/sudoers` has only a commented-out `env_keep` line for the SSH agent (checked on Debian 12/13 and Ubuntu 22.04/24.04, none of which use sudo-rs). Users are never asked for `--preserve-env`, and the current notice in `facts::session` that suggests it goes away.
- **Detection:** as root, walk `/proc/self` up through `PPid` (at most 64 steps) to the nearest ancestor whose `comm` is `sshd` or `sshd-session`. With a terminal, sudo's `use_pty` (set on all four distros) adds one extra `sudo` process to the chain; without one (`ssh host sudo ...`), none. That ancestor is the per-session process (`sshd-session: admin@pts/0` on Debian 13 with OpenSSH 10.0, `sshd: admin@pts/0` on the others; `@notty` without a terminal). Only that process is used: on Debian 13 the `[priv]` process above it has PPID 1, not the listener, so nothing may depend on reaching the listener.
- Its identity is its PID plus its start time (field 22 of `/proc/<pid>/stat`), so PID reuse cannot fake a match. `SSH_CONNECTION` is read from the `environ` of its child in the chain (readable by root; checked on Debian 13 and Ubuntu 24.04). The login user is that child's **real** uid (the first value of `Uid:` in `/proc/<pid>/status`): under `ssh host sudo ...` the child is `sudo` itself, whose effective uid is 0.
- **A session counts as new when** it is a different sshd session from the one recorded at apply **and** it started after `live_since`, the moment the changes went live. The second rule matters: a second terminal opened before apply also survives the sshd reload and the firewall's `established` rule, so it proves nothing.
- The session's server port must be one the host's sshd listens on: a `port` of `sshd -T` (the applied config) or, with socket activation, a stream `Listen` of `ssh.socket`. A login through another sshd (a rescue sshd on 2222, the sshd of a container that shares the host's PID namespace) also has an sshd ancestor, but proves nothing about the applied config.
- For a transaction with `user.admin`, the confirming user must be that admin.
- Refusals say why and print the command again: "This is not a new SSH login. tmux, screen and mosh sessions, the console, and ssh connections shared through ControlMaster all count as old. Open a new terminal and run: `ssh -t -o ControlPath=none -p 22 admin@203.0.113.10 sudo vps-ready confirm`".
- An `apply` with no sshd ancestor records no session; then any SSH session that started after `live_since` confirms.
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
- `PendingConfirm` + `rollback` (deadman-timeout, deadman-reboot or manual), then `restored`/`skipped`/`reloaded`, then `state rolled-back`; in the dead-man paths `restored` and `skipped` are also accepted with no `rollback` record before them (journal best effort);
- `Confirmed` + `rollback {reason: manual}` | `restored` | `reloaded` → `Confirmed`, then `state rolled-back (manual)`: the same pairs `Applied` has today.

Existing engine code that must learn the new states:
- `newest_applied()` (used by `rollback --last`) treats `Confirmed` like `Applied`, and prefers a `PendingConfirm` transaction over both.
- `ensure_finished()` refuses while a transaction is `PendingConfirm`, so `apply` cannot start a second one.
- The resume rule "no `rollback` record means `manual`" applies only when there is no `armed` record (see the dead-man rollback above).

**New journal events:**

```json
{"at":1792932000,"event":"armed","unit":"vps-ready-deadman-20261025T120000Z-1","boot_id":"0d5c...","deadline":{"boottime":1234,"wall":1792932900}}
{"at":1792932040,"event":"reloaded","reload":"sshd-reload"}
{"at":1792932041,"event":"state","state":"pending-confirm","unit":"vps-ready-deadman-20261025T120000Z-2","deadline":{"boottime":1575,"wall":1792932341},"live_since":1275,"session":{"pid":812,"start":10433}}
{"at":1792932100,"event":"extended","unit":"vps-ready-deadman-20261025T120000Z-3","deadline":{"boottime":1934,"wall":1792932700}}
{"at":1792932130,"event":"confirmed","session":{"pid":951,"start":12655},"user":"admin","client":"198.51.100.7"}
{"at":1792932130,"event":"state","state":"confirmed"}
```

A dead-man rollback that had to skip something:

```json
{"at":1792932400,"event":"rollback","reason":"deadman-timeout"}
{"at":1792932400,"event":"restored","resource":"file:/etc/ssh/sshd_config.d/00-vps-ready.conf"}
{"at":1792932400,"event":"skipped","resource":"authorized-keys:admin","by_hand":"copy files/2.before to /home/admin/.ssh/authorized_keys"}
{"at":1792932401,"event":"state","state":"rolled-back","reason":"deadman-timeout"}
```

- A pending-confirm transaction is finished in the M2 sense (its last line is a `state` record), but `apply` also refuses while one exists, and `rollback --last` picks it first.
- The state directory, lock, IDs and atomic writes are unchanged. The all-or-nothing safety check stays for a manual `rollback`; the dead-man paths use the per-resource rule above.

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
- A login through a jump host still has an sshd ancestor and can confirm. mosh, tmux, screen and the console cannot: `mosh-server` detaches and is reparented to PID 1, so it has no sshd ancestor.
- `userdel` fails while the admin has processes (exit 3, with the by-hand step). Restore order makes this harmless for access: the user is restored last.
- A dead-man rollback overwrites an edit the admin made during the window to a file of `ssh.server` or `firewall.inbound` (kept in `files/<n>.during`).
- Dead-man modules need systemd.

## Testing

**Layer 1:**
- Per module: `insta` snapshots of the plan and of every rendered file (drop-in, ruleset, unit, jail, sudoers); apply → next plan empty; apply → rollback → the tempdir tree equals the original.
- `ssh.server`: never `Port`, `ListenAddress`, `AllowGroups`; refuses without a keyed sudo user; the `Include` check on fixtures (missing, after a `Match`, after a conflicting line).
- `firewall.inbound`: the SSH ports are always accepted, for random port sets (proptest); not applicable with ufw active, firewalld active or legacy tables. Audit and fix agree: `FW-001` passes on the `nft -j` output of the loaded table (a fixture captured in the VM test).
- `user.admin`: option-prefixed keys skipped; `password` refused without a hash; sudoers file name has no `.`; `useradd` gets `--password '*'` only when `sshd -T` shows `usepam no`; `force_restore` is `false` on its backups and `true` on those of `ssh.server` and `firewall.inbound`.
- Engine: the new transitions; arm before the first change; a failed `systemd-run` ends the transaction before any backup; a crash after `armed` at every journal line (the dead-man entry point and the boot hook both finish the rollback); confirm racing the timer under the lock; extend re-arms under a new unit name and respects both caps; `rollback --last` picks pending, then the newest of applied and confirmed.
- Dead-man rollback on `FakeFs`: an edited `ssh.server` file is restored and its edit kept as `.during`; an edited `AuthorizedKeys` is skipped and journaled, the rest restored; every journal append failing (full disk) still restores everything; a resume with no `rollback` record keeps the dead-man reason; a rollback reload whose check fails is skipped.
- The binary-path check refuses a binary or a parent that is not root-owned, is group- or world-writable, or sits under `/home` or `/tmp`.
- Session detection on a fake `/proc`, built from the process trees seen on real hosts: `sudo` with `use_pty` (one extra process) and without a terminal (none); `sshd: user@pts/0` and `sshd-session: user@pts/0`; a Debian 13 `[priv]` with PPID 1; real uid from `Uid:` under `ssh host sudo`; no sshd ancestor (tmux, a mosh server under PID 1); PID reuse with a different start time; a session that started before `live_since`.
- `sshd-config`: parser property tests and include-order fixtures.

**Layer 2 (containers):** `ssh.bruteforce` full cycle (packages, jail, service; `SSH-008` passes; rollback). `user.admin` create and rollback. nftables syntax and load/delete in the container's own network namespace.

**Layer 3 (VMs): extend the existing QEMU/KVM harness; no Incus.** The milestone named Incus before `test/vm-cycle.sh` existed. QEMU with KVM already boots the four official cloud images on stock GitHub runners; Incus would add an install step, an image server and a second way to run the same VMs. What Incus would add, a command channel that does not depend on SSH, the dead-man tests do not need: a locked-out VM gets its SSH back when the timer fires, and the serial console log is already captured. The milestone description changes to "VM tests (QEMU/KVM)". New cycles, all with `--deadman 1m`:
1. `minimal` profile → confirm from a second SSH session as the admin → `SSH-001` to `SSH-007` and `FW-001` pass; root and password logins are refused; port 80 (forwarded to the host) times out; a forced DHCP lease renewal succeeds under the firewall.
2. Apply and do not confirm → within deadline + 10 s, the drop-in, the table and the user are gone and the old login works.
3. Apply, edit `00-vps-ready.conf` during the window, do not confirm → the drop-in is still reverted and the edit is in `files/<n>.during`.
4. `systemd-analyze verify` of `vps-ready-deadman.service` and `vps-ready-firewall.service` reports no ordering cycle; apply, reboot during the window → after boot, rolled back with `deadman-reboot` before sshd accepts the first login.
5. `confirm` from the applying session, from a session opened before apply, and through a `ControlMaster` connection are refused.
6. Ubuntu 24.04 (`ssh.socket`): the reload applies the drop-in to new connections.
The seed adds a key for root so test 1 can try a root login. QEMU's user network makes every connection come from 10.0.2.2, which is fine: sessions differ by sshd process, not by address. Session detection is tested over real `ssh` connections: Lima's Debian 13 shell uses vsock (`SSH_CONNECTION` is `UNKNOWN 65535 ...`), so a Lima shell is not a stand-in for an SSH login.

## PR sequence

Each PR leaves `main` releasable. Dangerous modules are registered only once the dead-man exists.

1. **`docs: plan M3`** (this document).

2. **`refactor: sshd-config crate`**: move the `sshd -T` parser; add the file reader. Tests: property tests, include fixtures. *Parallel with 3, 4, 5.*

3. **`feat(facts): SSH session from the process tree`**: `Session` with `SessionId`, client and server address, login user; drop the `--preserve-env` notice; `detect` shows it. Tests: fake `/proc` cases above. *Parallel.*

4. **`feat(resource): Service, User and AuthorizedKeys`**: the three kinds, their backups and restores. Tests: `FakeRunner` argv; round trips on a tempdir; symlinked `~/.ssh` refused. *Parallel.*

5. **`feat(engine): reloads, module verify and params`**: the new `Module` signature, `ModuleSteps`, `Reload`, `reloaded` events, rollback reloads; existing modules move over unchanged in behavior. *Parallel.*

6. **`feat(engine): dead-man states, arming and rollback entry points`** (needs 5): `PendingConfirm`, `Confirmed`, the new reasons and events, the transition and `newest_applied`/`ensure_finished` changes; arming with `systemd-run`, re-arming, the binary-path check; the boot hook; `--deadman` and `--deadman-boot` with the per-resource rule and best-effort journal; `apply --deadman`. A test-only dead-man module (behind the `testing` feature, so not in release binaries) exercises it; the VM cycles here only need the paths that do not confirm. Tests: the engine and dead-man rollback tests above; VM cycles 2 to 4 with the test module. A rollback reload skipped because its check failed gets a journal line and a `Progress` event (PR 5 only logs it).

7. **`feat(cli): confirm and the pending countdown`** (needs 3, 6): `confirm` with the session rule, `--extend` and its caps, the printed `ssh` line, refusals, the countdown, exit 4, `history` remaining time, manual rollback of a pending transaction; the VM harness gains a second SSH session and a root key. Tests: session tests; VM cycle 5.

8. **`feat(config): minimal and web profiles`** (needs 5): profile parsing, `extends`, `--profile`, the default selection without dead-man modules. Every module section's params are checked when the profile is parsed, through a `Module::check_params(&toml::Table)` default that does the same `deny_unknown_fields` parse, since a module that does not apply is never planned. *Parallel with 6 and 7.*

9. **`feat(modules): user.admin`** (needs 4, 7, 8). Layer 2 cycle.

10. **`feat(modules): ssh.server`** (needs 2, 7; `askama` arrives here): `fix` on `SSH-001` to `SSH-007`. VM cycles 1, 3 and 6. *Parallel with 9 and 11.*

11. **`feat(modules): firewall.inbound`** (needs 4, 7, 8): `fix` on `FW-001`. VM cycle 1 (firewall part, DHCP renewal). *Parallel with 9 and 10.*

12. **`feat(modules): ssh.bruteforce`** (needs 4, 8): `SSH-008` and its check kind; layer 2 cycle. *Can start as soon as 4 and 8 are in.*

13. **`chore: release v0.3.0`**: README, `architecture.md` (arm before change, no confirm code, `TxnState`), `decisions.md` (open question 2 decided), `testing.md`, `security-baseline.md` (5-minute window), milestone description, version bump. The release notes say that a v0.2 binary cannot read a journal with `reloaded` (or the other new events), so a downgrade must not be used to roll back a v0.3 transaction.

Waves: {2, 3, 4, 5} → {6, 8} → {7, 12} → {9, 10, 11} → 13.

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

## Fact check

Checked on VMs (Debian 13 with OpenSSH 10.0p2, Ubuntu 24.04 with 9.6p1; some also on Debian 12 with 9.2p1 and Ubuntu 22.04 with 8.9p1) and in the upstream docs:

| Claim | Where |
|---|---|
| sudo's `env_reset` drops `SSH_CONNECTION`; `env_keep` has only a commented SSH agent line; `use_pty` is set; no sudo-rs | Debian 12/13, Ubuntu 22.04/24.04 |
| `visudo -cf` exits 0 or 1; `sudoers.d` skips names with a `.` | the same four; `sudoers(5)` |
| First value wins; `Include` globs in lexical order | `sshd_config(5)` |
| `ssh.socket` enabled with `Accept=no`; `reload ssh.service` keeps the main PID, `ExecReload` runs `sshd -t` first | Ubuntu 24.04 |
| `SSH_CONNECTION` readable by root in the shell's `environ` | Debian 13, Ubuntu 24.04 |
| Process titles (`sshd-session:` on 10.0, `sshd:` before); Debian 13 `[priv]` has PPID 1; one extra `sudo` with a terminal | Debian 13, Ubuntu 24.04 |
| With `UsePAM yes`, locked passwords (`!`, `*`, `!*`) still accept key logins | Debian 13, Ubuntu 24.04 |
| `fail2ban-client -t` works; `defaults-debian.conf` sets `banaction = nftables` and `backend = systemd`; `inet f2b-table` at `filter - 1`, created on the first ban | Debian 13, Ubuntu 24.04 |
| With the drop-in, the sshd jail reads failed logins from the journal and bans into `inet f2b-table`; Debian 12's `defaults-debian.conf` sets only `enabled`; nft before 1.1 needs `netbase` for `port = ssh`; installing fail2ban enables it without starting it | Debian 12/13, Ubuntu 22.04/24.04 (containers) |
| `nft` missing on Debian 13, present on Ubuntu 24.04; `/etc/nftables.conf` starts with `flush ruleset`; `nftables.service` disabled; `iptables` is `iptables-nft` | Debian 13, Ubuntu 24.04 |
| A drop-policy table with `established` and the SSH port keeps the live session; a pre-conntrack flow without an accept rule can drop | Debian 13, Ubuntu 24.04 |
| `sshd-session` split and `PerSourcePenalties` on by default since 9.8 | OpenSSH 9.8 release notes |

Not yet checked; each is covered by a test in the PR that depends on it:
- On Debian 12 and Ubuntu 22.04: the `ssh.socket` and reload behavior (22.04 has no socket activation), the process titles, whether `nft` is preinstalled, and the conntrack behavior.
- The boot hook ordering (`DefaultDependencies=no`, before `ssh.socket`) on a real boot, and `systemd-analyze verify` of both units: VM cycle 4.
- That broadcast DHCPv4 replies need the `udp sport 67 dport 68` rule: VM cycle 1.

## Decided by the owner (2026-10-24)

1. One transaction and one confirm for `user.admin` + `ssh.server` + `firewall.inbound`, rather than three challenges.
2. Plain `apply` (no `--profile`, no `--module`) leaves the dead-man modules out.
3. No confirm code.
4. `sudo = "nopasswd"` as the default for a user `user.admin` creates; an existing user with sudo keeps it; `password` only for accounts that already have one.
5. nftables in our own table and unit on Ubuntu too, and not applicable when ufw is active.
6. A 5-minute default window, `1m` to `30m`, and exit code 4 for "still pending".
7. Accept input from `docker0` and `br-*` when Docker is present.
8. Drop "Incus" from the milestone in favor of the existing QEMU harness.
9. In the dead-man paths, files of `ssh.server` and `firewall.inbound` are restored even if the admin edited them (the edit kept as `.during`).
