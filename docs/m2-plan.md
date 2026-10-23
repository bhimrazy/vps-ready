# M2 plan: engine and safe modules (v0.2.0)

M2 adds `plan`, `apply`, `rollback` and `history`, the engine behind them, and two modules that cannot lock anyone out. It is the subset of [the architecture](architecture.md) that those two modules need; the rest waits for the milestone that needs it (see [Deferred](#deferred-from-the-architecture)).

## Decisions

### Modules: `kernel.sysctl` and `updates.auto`

| Module | Changes | Fixes | Why first |
|---|---|---|---|
| `kernel.sysctl` | `/etc/sysctl.d/90-vps-ready.conf` and the running values under `/proc/sys` | the 14 `KRN-*` and `NET-*` controls | Files and `/proc/sys` only: no commands, no network, no packages, so it exercises the whole engine with the smallest surface. Not applicable in a container (`facts.sysctl` is `None`) |
| `updates.auto` | installs `unattended-upgrades` if missing; writes `/etc/apt/apt.conf.d/52vps-ready` | `UPD-001` | Adds the one command-based resource (a package) and a validate step. Debian and Ubuntu only. Testable in the existing containers |

Not in M2:
- `base.time` (switching timesyncd to chrony is a package swap; changing the time zone changes cron and log times users see).
- `base.swap` (allocates disk and edits `/etc/fstab`, where a bad line can stop the next boot; Btrfs and containers need special cases).
- journald settings (needs a restart of `systemd-journald` and has no control yet).

They can follow in a v0.2.x once the engine is proven.

**`kernel.sysctl` details:**
- It manages exactly the keys of the controls marked `fix = "kernel.sysctl"`, with these values:
  - `kptr_restrict=1`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=2`, `yama.ptrace_scope=1`, `randomize_va_space=2`, `perf_event_paranoid=2`;
  - `fs.protected_{symlinks,hardlinks,fifos,regular}=1`, `fs.suid_dumpable=0`;
  - `tcp_syncookies=1`, `conf.all.accept_source_route=0`, `icmp_echo_ignore_broadcasts=1`.
- `kptr_restrict=1`, not the baseline's `2`: `2` hides `/proc/kallsyms` from root too and breaks `perf` and `bpftrace`. Ubuntu ships `1`.
- A key goes into the drop-in only if its running value fails the control or the existing drop-in already lists it. Without this, a distro's stricter value (Ubuntu's `perf_event_paranoid=4`) would be lowered at the next boot. Keeping keys the drop-in already lists keeps a second run a no-op.
- Skipped keys:
  - a key the kernel does not have (e.g. no Yama) is skipped;
  - a key that could not be read (non-root `plan`) is skipped with a note in the plan.
- Values the kernel will not take back at runtime are not used: `unprivileged_bpf_disabled=1` and `ptrace_scope=3` cannot be lowered until a reboot, so rollback could not restore them. A unit test lists these values and fails if the module emits one.
- It never writes `ip_forward`, `accept_ra` or `rp_filter` (see the baseline's "Never set"). A unit test enforces this.
- Known limits:
  - A file that sorts after `90-` in `sysctl.d` (or Debian 12's `/etc/sysctl.conf` via `99-sysctl.conf`) can override the drop-in at boot. M2 checks the running values only, so such a key shows up again in the next plan.
  - A runtime value written for a key that is not in the drop-in reverts at reboot and shows up again in the next plan.
  - Another tool can change a key after apply (apport sets `fs.suid_dumpable=2` at boot). `rollback` then refuses that key (see [Rollback](#rollback)).

**`updates.auto` details:**
- The drop-in sets `APT::Periodic::Enable "1"`, `APT::Periodic::Update-Package-Lists "1"` and `APT::Periodic::Unattended-Upgrade "1"`.
  - `Enable` is needed because the captured Ubuntu 24.04 image sets it to `"0"`.
  - It does not set `Unattended-Upgrade::Automatic-Reboot`: `false` is already the default, and setting it would override an admin's own choice. `UPD-001` does not check it.
  - apt reads `apt.conf.d` in order, so `52` overrides the package's `20auto-upgrades`.
- Installing the package:
  - It runs `apt-get update`, then `apt-get install -y --no-install-recommends`, the way Ansible's `update_cache` does. A fresh image's package lists can be missing or stale.
  - Both commands run under `DEBIAN_FRONTEND=noninteractive` with `-o DPkg::Lock::Timeout=300` (cloud-init may still hold the dpkg lock on first boot) and a 10-minute command timeout.
- If systemd has apt's timers disabled or masked, the module does not touch them: the plan says so, and `UPD-001` keeps failing. Turning timers back on needs a `Service` resource, which comes in M3.

### Resources: a closed enum, not trait objects

```rust
pub enum Resource {
    File(File),       // whole-file content we own: path, bytes, mode, uid, gid, validate: Option<Validate>
    Sysctl(Sysctl),   // key, value; reads and writes /proc/sys/<key with dots as slashes>
    Package(Package), // apt package name (Debian family only in M2)
}

impl Resource {
    pub fn id(&self) -> String;                                        // "file:/etc/...", "sysctl:kernel.kptr_restrict", "package:unattended-upgrades"
    pub fn reversibility(&self) -> Reversibility;
    pub fn diff(&self, sys: Sys) -> Result<Option<Change>, ResourceError>; // None = already in the desired state
    pub fn snapshot(&self, sys: Sys) -> Result<Backup, ResourceError>;
    pub fn apply(&self, sys: Sys) -> Result<(), ResourceError>;
}

pub enum Backup {                       // serde: written to the journal
    File { path: PathBuf, n: u32, original: Option<FileCopy> },  // bytes in files/<n>.before|after; None = did not exist
    Sysctl { key: String, value: String, applied: String },
    Package { name: String, was_installed: bool },
}
pub struct FileCopy { mode: u32, uid: u32, gid: u32 }
pub fn restore(sys: Sys, txn_dir: &Path, backup: &Backup) -> Result<(), ResourceError>;
```

Why:
- **Restore needs only the journal.** `rollback --last` runs in a later process that may be a newer version, so restoring must not rebuild modules or depend on what a module would plan today. Restore is a function of `Backup`.
- **The set of kinds is closed** (the architecture already lists them), so an enum gives exhaustive `match`, free `serde` for the journal and `plan --json`, and no `typetag`-style dependency.
- `DropIn` is a `File`: whole-file content at a path we own. `LineInFile` and `Command` are not added (nothing in M2 needs them).
- `Reversibility` stays: `File` and `Sysctl` are `Reversible`. `Package` is `Partial`, because rollback leaves an installed package installed (removing it could take dependencies with it) and the plan says so. `Irreversible` has no user until `base.update`.

**`File`:**
- `File::diff` lstats the target. At plan time it refuses:
  - a symlink or any other non-regular file;
  - a missing parent directory.
- M2 `File` resources only target paths that vps-ready owns, and creates: its two drop-ins. That is why snapshots skip xattrs, ACLs and SELinux labels; a file vps-ready created has none of its own to lose.
- Restoring a file goes through `write_atomic` with the journaled mode, uid and gid. Restoring "did not exist" is `remove` followed by an fsync of the directory.

`Change` is what the plan shows: `{ id, summary: String, diff: Option<String>, reversibility }`. `diff` is a unified diff (`similar`) for files; everything else is the one-line summary.

`Sys` is `#[derive(Clone, Copy)] pub struct Sys<'a> { pub fs: &'a dyn Fs, pub runner: &'a dyn Runner }`.

### Modules

```rust
pub trait Module {
    fn id(&self) -> &'static str;           // "kernel.sysctl"
    fn title(&self) -> &'static str;
    fn why(&self) -> &'static str;
    fn applicable(&self, facts: &Facts) -> Applicability; // Applicable | NotApplicable { reason }
    fn plan(&self, facts: &Facts, sys: Sys) -> Result<Vec<Resource>, ModuleError>; // may read, never write
}
```
A registry `modules::all() -> &[&dyn Module]` lists them in a fixed order. No `params`, `requires`, `conflicts`, `validate` or `verify` methods in M2:
- Parameters arrive with profiles in M3.
- Ordering and conflicts are not needed with two independent modules.
- Validation is per file (`File::validate`).
- Verification is generic (below).

Controls gain an optional `fix = "<module id>"` field in the catalog TOML. `audit` prints `fix: sudo vps-ready apply --module <id>` under a failed control that has one.

### Engine flow (M2)

`apply`:
1. Take the lock.
2. Refuse if any transaction is unfinished (see [State layout](#state-layout-m2)).
3. Collect facts and plan. An empty plan prints "nothing to do", creates no transaction directory and exits 0.
4. Print the plan and ask `Apply N changes? [y/N]`. A non-TTY without `--yes` is an error.
5. Re-run `diff()` on every resource. If the set of changes differs from what was shown, abort with exit 2.
6. Create the transaction and run it:

```
create txn/<id>/ and journal.jsonl; fsync journal.jsonl, txn/<id>/ and txn/
journal "begin"
for each resource with a change, in plan order:
    backup = snapshot()
    File: write files/<n>.before (if the file existed) and files/<n>.after, fsync them,
          then run validate on files/<n>.after if set
    journal "backup"                         (fsync)
    apply()
    journal "applied"                        (fsync)
verify: diff() of every resource is None again
on any error or a failed verify: rollback (below) with reason apply-failed or verify-failed
else: journal "state applied"
then: re-run the audit for controls whose fix is in the plan and print it (informational, never triggers rollback)
```

The `backup` line is fsynced before the resource is touched, and `.before` before that line. After a crash, every resource that may have changed has a backup on disk.

There is no reload step: neither module needs one (`/proc/sys` is live, and apt reads its config on every run). Reload arrives with sshd in M3.

**Atomic write** (`Fs::write_atomic`):
1. Refuse if the target is a symlink.
2. Create `.<name>.vps-ready-tmp` in the same directory (`O_EXCL`).
3. Write; `fchmod`/`fchown` to the requested mode and owner; `fsync`.
4. `rename` over the target; `fsync` the directory.

All with `std` (`File::sync_all`, `std::os::unix::fs::fchown`). A crash can leave the temp file; the next `write_atomic` of that path removes it first.

**Lock:**
- `/var/lib/vps-ready/lock`, taken with `File::try_lock()` (std since Rust 1.89; the MSRV is 1.98).
- It does not wait: a second `apply` or `rollback` fails at once with "another vps-ready is running".
- The kernel drops the lock when the process exits, including on a crash. Rust opens files with `O_CLOEXEC`, so a child process such as `apt-get` cannot keep holding it.
- `plan`, `history` and `audit` do not lock.

### State layout (M2)

```
/var/lib/vps-ready/                 0700 root:root
    lock
    txn/<id>/
        journal.jsonl               append-only, one JSON object per line, fsync per line
        files/<n>.before            original bytes of the n-th backed-up file (absent if it did not exist)
        files/<n>.after             bytes vps-ready wrote (also what validate runs on)
```

- The state directory is checked with `lstat`. vps-ready refuses to run if it is a symlink, not owned by root, or writable by group or others.
- `<id>` is the UTC start time, `20261023T114246Z`. The lock rules out two at once; if the directory exists, `-2`, `-3` is appended. Sorting by name is sorting by time. This needs a small days-to-date helper (with a unit test), not the `ulid` crate.
- `files/<n>` is numbered, not an escaped path: the journal maps `n` to the path, so no escaping scheme is needed.

Journal records are a `#[serde(tag = "event")]` enum, and every line has `at` in Unix seconds. Line order is the sequence:

```json
{"at":1792745000,"event":"begin","version":"0.2.0","modules":["kernel.sysctl"]}
{"at":1792745000,"event":"backup","resource":"file:/etc/sysctl.d/90-vps-ready.conf","backup":{"kind":"file","path":"/etc/sysctl.d/90-vps-ready.conf","n":1,"original":null}}
{"at":1792745000,"event":"applied","resource":"file:/etc/sysctl.d/90-vps-ready.conf"}
{"at":1792745000,"event":"backup","resource":"sysctl:kernel.kptr_restrict","backup":{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0","applied":"1"}}
{"at":1792745000,"event":"applied","resource":"sysctl:kernel.kptr_restrict"}
{"at":1792745001,"event":"state","state":"applied"}
```

Reading the journal:
- Unknown fields are ignored (an older binary can read a newer journal). An unknown event kind is an error.
- A final line without a newline is a torn write from a crash: it is ignored, and removed from the file before a resumed transaction appends to it. Any other unparseable line is an error.

Transaction states:
- **State** is the last `state` record, or `planned` if there is none.
- M2 uses the architecture's `TxnState` without the dead-man variants: `Planned`, `Applied`, `RolledBack { reason: ApplyFailed | VerifyFailed | Manual }`. Transitions go through one `(state, event)` match. M3 adds `PendingConfirm`, `Confirmed` and `DeadmanTimeout`.
- **Unfinished** means the last journal line is not a `state` record. That covers a crash during apply and a crash during a rollback. While any transaction is unfinished:
  - `apply` refuses and says to run `vps-ready rollback --txn <id>`. It never rolls back on its own.
  - `rollback --last` picks the unfinished transaction and resumes it.

### Rollback

- `rollback --last` picks the unfinished transaction if there is one, otherwise the newest in state `applied`. `rollback --txn <id>` picks that one. It is an error if the transaction is already rolled back.
- **Order:** backups are restored in reverse journal order, with a `restored` line (fsynced) after each, then `state rolled-back`. A rerun after a crash skips backups that already have a `restored` line.
- **Safety check first**, on every backup not yet restored:
  - **File:** the current content must equal `.after` or `.before`. If the file did not exist before, it must be absent or equal `.after`. Mode and owner are not compared; restore sets them back from the journal.
  - **Sysctl:** the current value must equal the applied value or the original.
  - Both values are allowed because a crash may have happened just before or after `apply()`.
- **If the check fails:** nothing is restored. The command lists each resource that changed, the transaction's `files/` paths, and the by-hand step for each, e.g. "copy `files/1.before` to `/etc/...`" or "`sysctl -w fs.suid_dumpable=0`". There is no `--force` in M2. This also stops an older transaction from undoing a newer one on the same file.
- `Package` restore is a no-op; the plan already labeled it `partial`.
- An `apt-get` timeout kills `apt-get`, not `dpkg`, so the dpkg database may then need `dpkg --configure -a`, which rollback does not run.

### CLI and plan rendering

```
vps-ready plan     [--module ID]... [--json]
vps-ready apply    [--module ID]... [--yes]
vps-ready rollback (--last | --txn ID)
vps-ready history  [--json]
```

- No `--module` means every applicable module. `plan --module X` for a module that does not apply shows it as not applicable. `apply --module X` for such a module is an error that gives the reason.
- `apply` and `rollback` require root (the existing `/proc/self/status` check).
- `plan` does not; as non-root it skips the sysctl keys it cannot read and says so.
- `history` prints one line per transaction (ID, state, modules, number of changes), newest first.

Exit codes:

| Code | `plan` | `apply` | `rollback` |
|---|---|---|---|
| 0 | the plan was printed | applied, or nothing to do | rolled back |
| 1 | | failed and rolled back cleanly | |
| 2 | error | error: usage, lock busy, not root, unfinished transaction, module not applicable, plan changed after the prompt | error, including refused by the safety check (nothing restored) |
| 3 | | failed, and the rollback did not complete | did not complete |

When exit code 3 is returned, the message names the transaction directory and the files left to restore by hand.

Text plan (an `insta` snapshot pins it); `+` create, `~` change, colors only on a TTY:

```
kernel.sysctl: Harden kernel settings (fixes KRN-001, KRN-003, NET-001)
  + /etc/sysctl.d/90-vps-ready.conf (0644 root:root)                     reversible
      @@ -0,0 +1,3 @@
      +kernel.kptr_restrict = 1
      +kernel.unprivileged_bpf_disabled = 2
      +net.ipv4.tcp_syncookies = 1
  ~ kernel.kptr_restrict 0 -> 1                                           reversible
  ~ kernel.unprivileged_bpf_disabled 0 -> 2                               reversible
  ~ net.ipv4.tcp_syncookies 0 -> 1                                        reversible
updates.auto: not applicable (apt not found)

4 changes in 1 module. Run `sudo vps-ready apply` to make them.
```

The reversibility column is an exhaustive `match`, with no `_ =>` arm. `plan --json` serializes the same `Plan` struct.

### Idempotency and rollback tests

**Fixtures.** Today's `testdata/hosts` are container captures: no `/proc/sys` values (`facts.sysctl` is `None`) and no `unattended-upgrades`. So module tests do not use them as hosts:
- They build `Facts` by hand, as `root_hint_covers_root_only_kernel_settings` in `cli` already does.
- They write to `RealFs` on a tempdir, which exercises the real write path, including `/proc/sys/...` as plain files.
- Package state comes from a `FakeRunner` answering `dpkg-query`.
- Captures from real VMs come with M3's VM tests.

**Tests:**
- **Per module:** an `insta` snapshot of the first plan; apply → the next plan is empty; apply → rollback → the tempdir tree (contents and modes) equals the original.
- **Audit and fix agree:** after apply, re-collect the sysctl facts from the tempdir and audit. Every control whose `fix` is the module passes. A catalog test checks that every `fix` names a registered module and that each sysctl value is in its control's `one_of`.
- **Property test** (`kernel.sysctl`): random starting values for the 14 keys and a random pre-existing drop-in; apply → the next plan is empty, and apply → rollback restores.
- **Failure injection (engine, on `FakeFs`):** `FakeFs` can fail the n-th write, rename, remove or journal append. For every n:
  - if the failure is in apply, the engine ends `rolled-back(apply-failed)` with the tree restored;
  - if it is in a rollback, the exit code is 3 and a rerun of `rollback` finishes the job.
- **Crash simulation:** truncate the journal after every line and in the middle of every line, then check that `apply` refuses and `rollback --last` restores the original tree.
- **Safety check:** rollback refuses a changed file and a changed sysctl. Rolling back transaction 1 after transaction 2 changed the same file is refused.
- **Containers (layer 2, `updates.auto` only):** `apply --yes` → `plan --json` has no changes → `UPD-001` passes → `rollback --last` → the managed files match a copy taken before. The package stays installed by design, so this compares the managed files, not a full `/etc` diff.
- `kernel.sysctl` cannot run in a container. Until the M3 VM tests, its PR records a manual run on a throwaway VM (apply, reboot, audit, rollback).

## PR sequence

Each PR builds on the previous one and leaves `main` releasable. Every user-visible command arrives in PR 7, so earlier PRs change no behavior.

1. **`docs: plan M2`** (this document).
   - Out: code.

2. **`feat(sys): writes through Fs`**
   - Goal: `Fs` gains `write_atomic(path, bytes, owner: FileOwner{mode,uid,gid})`, `write` (truncate in place, for `/proc/sys` only), `append_sync` (for the journal), `remove`, `create_dir_all(path, mode)`, and `sync_dir`. Add the `Sys` struct.
   - `FakeFs`: becomes mutable behind a `Mutex`, keeps per-file metadata, and can fail the n-th write, rename, remove or append. This is for the engine's failure tests; module tests use `RealFs` on a tempdir.
   - Files: `sys/mod.rs`, `sys/fake.rs`.
   - Tests: `RealFs` on a tempdir (content, mode, overwrite leaves no temp file, symlink target refused, a failed write leaves the original); the same assertions against `FakeFs`.
   - Out: lock, SELinux contexts, xattrs, owner changes in tests (non-root CI cannot `chown`; the call is covered on `FakeFs` and in containers).

3. **`feat(resource): File and Sysctl resources`**
   - Goal: `src/resource/` with `Resource`, `Change`, `Reversibility`, `Backup`, `restore`, `ResourceError`; the `File` and `Sysctl` kinds; the plan-time refusals for `File`; unified diffs via `similar` (new dependency).
   - Tests: diff none/some; symlink, non-regular file and missing parent refused; snapshot → apply → restore round trip (including a file that did not exist); `Backup` serde round trip.
   - Out: `Package`, validate, engine.

4. **`feat(engine): state directory, lock and journal`**
   - Goal: state dir creation and `lstat` check; the lock; transaction IDs; the journal writer and reader (fsync per line, torn last line, unknown fields and events); `TxnState` transitions; "unfinished" detection.
   - Tests: the permission check refuses each bad case; lock contention on a tempdir (two `try_lock`s); the date helper; journal round trip, a torn final line ignored and a bad middle line rejected; illegal state transitions.
   - Out: apply, rollback.

5. **`feat(engine): apply, rollback and history`**
   - Goal: `plan` over `&[&dyn Module]` (a test-only module is enough here); `apply` with the durability ordering above, verify and automatic rollback; `rollback` with the safety check and resume; `history`.
   - Tests: failure injection, crash simulation and safety-check tests from above.
   - Out: real modules, CLI.

6. **`feat(modules): kernel.sysctl`**
   - Goal: the `Module` trait, the registry, `kernel.sysctl`, `fix = "kernel.sysctl"` on the 14 controls, `fix` in `audit` output.
   - Tests: idempotency and rollback on a tempdir; the `insta` plan snapshot; audit and fix agree; never `ip_forward`/`accept_ra`/`rp_filter`; no runtime-sticky values; absent and unreadable keys skipped; the property test.
   - Out: the CLI to run it (next PR).

7. **`feat(cli): plan, apply, rollback and history`**
   - Goal: the four commands, the text and JSON plan, the prompt and the re-check after it, the root check, the lock, exit codes.
   - Tests:
     - `insta` snapshots of the rendered plan and of `history`;
     - `assert_cmd`: `apply` without root exits 2 and changes nothing; `plan --json` parses; `rollback` without `--last` or `--txn` is a usage error.
   - Manual: a throwaway VM run of `kernel.sysctl` noted in the PR.
   - Out: `updates.auto`.

8. **`feat(resource): Package and file validation`**
   - Goal: an apt-only `Package` resource (`dpkg-query` for state; `apt-get update` then `apt-get install`); `File::validate`, which runs a command on `files/<n>.after` before the real file is written.
   - Tests: `FakeRunner` sees exactly the expected argv and environment; a validate failure aborts before any write; `Package` restore is a no-op.
   - Out: other package managers, the platform layer.

9. **`feat(modules): updates.auto`**
   - Goal: the module (validate with `apt-config -c <files/n.after> dump`), `fix = "updates.auto"` on `UPD-001`, and the container cycle in the `containers` CI job.
   - Tests: plans with the package missing and present; the drop-in contents pinned by `insta`; the container cycle.
   - Out: timers.

10. **`chore: release v0.2.0`**
    - Goal: README command table and "today" notes, `testing.md` (what layer 2 now covers), `CONTRIBUTING.md` (adding a module), version bump.
    - Out: anything new.

## Deferred from the architecture

The architecture describes v1. For M2 these parts are not needed or are simpler:

| Architecture | M2 | When |
|---|---|---|
| Platform layer (`PkgManager`, `ServiceManager`, `Firewall`, `Sshd`) | `Package` calls apt directly; modules check `facts.os` | When a second package manager or init system is supported (M6). `Sshd` and `Firewall` in M3 |
| Profiles (TOML, `extends`, `schemars` JSON Schema), `/etc/vps-ready/config.toml` | `--module` selects modules; no parameters | M3, when `user.admin` needs keys; JSON Schema when an editor or the wizard needs it |
| Module `params`, `requires`/`conflicts` + topological sort, `validate`, `verify`, `needs_deadman` | Fixed registry order; per-file validate; generic verify | M3 (`user.admin` before `ssh`) |
| `plan --out plan.json` → `apply plan.json` with hash checks | `apply` plans under the lock, shows the plan, and re-checks it after the prompt | When cloud-init export needs it (M5), if ever |
| `askama` templates | Two small generated files, built with `format!` and pinned by `insta` | M3, with the sshd drop-in |
| `meta.json`, `plan.json`, `diff.patch`, `state.json`, `/var/log/vps-ready/` | The journal is the record; logs go to stderr | `state.json` with `drift` (M6) |
| ULID transaction IDs, `rustix` for `fsync`/`flock` | UTC timestamp IDs; `std` has `sync_all`, `fchown` and `File::try_lock` | Not needed |
| SELinux context in snapshots | Mode, owner, bytes, on files vps-ready owns | With Rocky/Alma (M6) |
| `Service`, `User`, `AuthorizedKeys`, `FirewallRuleset` resources; reload step | Not needed by M2 modules | M3 |

## Decided with the owner

1. Two modules in M2 (`kernel.sysctl`, `updates.auto`). `base.time`, `base.swap` and journald come after v0.2.0.
2. `kptr_restrict=1`, not `2`.
3. Rollback leaves a package that vps-ready installed in place, and the plan labels it `partial`.
4. No profile file in M2; `--module` selects modules.
5. Exit code 3 when a rollback is incomplete.
6. `apply` refuses while any transaction is unfinished, including a half-rolled-back one.
7. `updates.auto` always runs `apt-get update` before installing, and its drop-in does not set `Automatic-Reboot`.
