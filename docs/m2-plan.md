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
  - `kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=2`, `yama.ptrace_scope=1`, `randomize_va_space=2`, `perf_event_paranoid=2`;
  - `fs.protected_{symlinks,hardlinks,fifos,regular}=1`, `fs.suid_dumpable=0`;
  - `tcp_syncookies=1`, `conf.all.accept_source_route=0`, `icmp_echo_ignore_broadcasts=1`.
- A key goes into the drop-in only if its running value fails the control or the existing drop-in already lists it. Without this, a distro's stricter value (Ubuntu's `perf_event_paranoid=4`) would be lowered at the next boot. Keeping keys the drop-in already lists keeps a second run a no-op.
- Values the kernel will not take back at runtime are not used: `unprivileged_bpf_disabled=1` and `ptrace_scope=3` cannot be lowered until a reboot, so rollback could not restore them. A unit test lists these values and fails if the module emits one.
- It never writes `ip_forward`, `accept_ra` or `rp_filter` (see the baseline's "Never set"). A unit test enforces this.
- Known limit: a file that sorts after `90-` in `sysctl.d` (or Debian 12's `/etc/sysctl.conf` via `99-sysctl.conf`) can override the drop-in at boot. M2 checks the running values only.

**`updates.auto` details:**
- The drop-in sets `APT::Periodic::Update-Package-Lists "1"`, `APT::Periodic::Unattended-Upgrade "1"` and `Unattended-Upgrade::Automatic-Reboot "false"`. apt reads `apt.conf.d` in order, so `52` overrides the package's `20auto-upgrades`.
- The package is installed with `apt-get install -y --no-install-recommends` under `DEBIAN_FRONTEND=noninteractive` with `-o DPkg::Lock::Timeout=300` (cloud-init may still hold the dpkg lock on first boot) and a 10-minute command timeout.
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
    File { path: PathBuf, original: Option<FileCopy> },  // None = the file did not exist
    Sysctl { key: String, value: String },
    Package { name: String, was_installed: bool },
}
pub fn restore(sys: Sys, backup: &Backup) -> Result<(), ResourceError>;
```

Why:
- **Restore needs only the journal.** `rollback --last` runs in a later process that may be a newer version, so restoring must not rebuild modules or depend on what a module would plan today. Restore is a function of `Backup`.
- **The set of kinds is closed** (the architecture already lists them), so an enum gives exhaustive `match`, free `serde` for the journal and `plan --json`, and no `typetag`-style dependency.
- `DropIn` is a `File`: whole-file content at a path we own. `LineInFile` and `Command` are not added (nothing in M2 needs them).
- `Reversibility` stays: `File` and `Sysctl` are `Reversible`. `Package` is `Partial`, because rollback leaves an installed package installed (removing it could take dependencies with it) and the plan says so. `Irreversible` has no user until `base.update`.

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
2. Collect facts.
3. Plan.
4. Print the plan; ask `Apply N changes? [y/N]` (a non-TTY without `--yes` is an error).
5. Create the transaction and run it:

```
for each resource with a change, in plan order:
    backup = snapshot()          -> journal "backup" (fsync) before anything is written
    File: write the new bytes to the txn dir, run validate on that copy if set
    apply()                      -> journal "applied"
verify: diff() of every resource is None again
on any error or a failed verify: restore the journaled backups in reverse -> state rolled-back
else -> state applied
then: re-run the audit for controls whose fix is in the plan and print it (informational, never triggers rollback)
```

There is no reload step: neither module needs one (`/proc/sys` is live, and apt reads its config on every run). Reload arrives with sshd in M3.

**Atomic write** (`Fs::write_atomic`):
1. Refuse if the target is a symlink.
2. Create `.<name>.vps-ready-tmp` in the same directory (`O_EXCL`).
3. Write; `fchmod`/`fchown` to the requested mode and owner; `fsync`.
4. `rename` over the target; `fsync` the directory.

All with `std` (`File::sync_all`, `std::os::unix::fs::fchown`). A crash can leave the temp file; the next `write_atomic` of that path removes it first.

**Lock:** `/var/lib/vps-ready/lock`, `File::try_lock()` (std since Rust 1.89, MSRV is 1.98). It does not wait: a second `apply` or `rollback` fails at once with "another vps-ready is running". The kernel drops the lock when the process exits, including on a crash. `plan`, `history` and `audit` do not lock.

### State layout (M2)

```
/var/lib/vps-ready/                 0700 root:root; refuse to run if not root-owned or group/other-writable
    lock
    txn/<id>/
        journal.jsonl               append-only, one JSON object per line, fsync per line
        files/<n>.before            original bytes of the n-th backed-up file (absent if it did not exist)
        files/<n>.after             bytes vps-ready wrote (also what validate runs on)
```

- `<id>` is the UTC start time, `20261023T114246Z`. The lock rules out two at once; if the directory exists, `-2`, `-3` is appended. Sorting by name is sorting by time. This needs a small days-to-date helper (with a unit test), not the `ulid` crate.
- `files/<n>` is numbered, not an escaped path: the journal maps `n` to the path, so no escaping scheme is needed.

Journal records (`#[serde(tag = "event")]` enum; every line has `seq` and `at` in Unix seconds):

```json
{"seq":1,"at":1792745000,"event":"begin","version":"0.2.0","modules":["kernel.sysctl"]}
{"seq":2,"at":1792745000,"event":"backup","resource":"file:/etc/sysctl.d/90-vps-ready.conf","backup":{"kind":"file","path":"/etc/sysctl.d/90-vps-ready.conf","original":null},"n":1}
{"seq":3,"at":1792745000,"event":"applied","resource":"file:/etc/sysctl.d/90-vps-ready.conf"}
{"seq":4,"at":1792745000,"event":"backup","resource":"sysctl:kernel.kptr_restrict","backup":{"kind":"sysctl","key":"kernel.kptr_restrict","value":"0"}}
{"seq":5,"at":1792745000,"event":"applied","resource":"sysctl:kernel.kptr_restrict"}
{"seq":6,"at":1792745001,"event":"state","state":"applied"}
```

- **State** is the last `state` record, or `planned` if there is none. M2 uses the architecture's `TxnState` without the dead-man variants: `Planned`, `Applied`, `RolledBack { reason: ApplyFailed | VerifyFailed | Manual }`. Transitions go through one `(state, event)` match. M3 adds `PendingConfirm`, `Confirmed` and `DeadmanTimeout`.
- **Unfinished transaction:** if the newest transaction is still `planned` (a crash or power cut mid-apply), `apply` refuses and says to run `vps-ready rollback --txn <id>`. It does not roll back on its own.

### Rollback

- `rollback --last` picks the newest transaction in state `applied`; `rollback --txn <id>` picks that one (also a `planned` one left by a crash). It is an error if the transaction is already rolled back.
- **Order:** backups are restored in reverse journal order. A `restored` record is written after each, then `state rolled-back(manual)`. Rerunning after a crash resumes: a resource already back to its original is skipped.
- **Safety check first:** for every backed-up file, the current content must equal `<n>.after` or `<n>.before`. For every sysctl, the current value must equal the applied or the original value. If anything was changed since (by the admin or a later transaction), nothing is restored and the command lists what differs. There is no `--force` in M2. This also stops an older transaction from undoing a newer one on the same file.
- `Package` restore does nothing when the package was installed by this transaction; the plan already labeled it `partial`.

### CLI and plan rendering

```
vps-ready plan     [--module ID]... [--json]
vps-ready apply    [--module ID]... [--yes]
vps-ready rollback (--last | --txn ID)
vps-ready history  [--json]
```

- No `--module` means every applicable module. `apply` and `rollback` require root (the existing `/proc/self/status` check).
- `plan` does not; as non-root it may show a few sysctl keys as unknown.

Exit codes:

| Code | `plan` | `apply` |
|---|---|---|
| 0 | the plan was printed | applied, or nothing to do |
| 1 | | failed and rolled back cleanly |
| 2 | error | error (usage, lock busy, not root, unfinished transaction) |
| 3 | | failed and the rollback did not complete. The message names the transaction directory and the files left to restore by hand |

Text plan (an `insta` snapshot pins it); `+` create, `~` change, colors only on a TTY:

```
kernel.sysctl: Harden kernel settings (fixes KRN-001, KRN-003, NET-001)
  + /etc/sysctl.d/90-vps-ready.conf (0644 root:root)                     reversible
      @@ -0,0 +1,3 @@
      +kernel.kptr_restrict = 2
      +kernel.unprivileged_bpf_disabled = 2
      +net.ipv4.tcp_syncookies = 1
  ~ kernel.kptr_restrict 0 -> 2                                           reversible
  ~ kernel.unprivileged_bpf_disabled 0 -> 2                               reversible
  ~ net.ipv4.tcp_syncookies 0 -> 1                                        reversible
updates.auto: not applicable (apt not found)

4 changes in 1 module. Run `sudo vps-ready apply` to make them.
```

The reversibility column is an exhaustive `match`, with no `_ =>` arm. `plan --json` serializes the same `Plan` struct.

### Idempotency and rollback tests

- **Per module, per host fixture** (`testdata/hosts/{ubuntu-24.04,debian-12,debian-13}`):
  - `FakeFs` seeded from the fixture root;
  - `insta` snapshot of the first plan;
  - apply → plan is empty;
  - apply → rollback → the `FakeFs` (contents and metadata) equals the original.
- **Audit and fix agree:** after apply on a fake, re-collect facts and audit. Every control whose `fix` is the module passes. A catalog test checks that every `fix` names a registered module and that each sysctl value is in its control's `one_of`.
- **Property test** (`kernel.sysctl`): random starting values for the 14 keys and a random pre-existing drop-in; apply→plan empty and apply→rollback restores.
- **Failure injection:** `FakeFs` can fail the n-th write. For every n, the engine ends `rolled-back(apply-failed)` with the tree restored, and the journal replays to the same state.
- **Containers (layer 2, `updates.auto` only):** `apply --yes` → `plan --json` has no changes → `UPD-001` passes → `rollback --last` → the managed files match a copy taken before. The package stays installed by design, so this compares the managed files, not a full `/etc` diff.
- `kernel.sysctl` cannot run in a container. Until the M3 VM tests, its PR records a manual run on a throwaway VM (apply, reboot, audit, rollback).

## PR sequence

Each PR builds on the previous one and leaves `main` releasable. Every user-visible command arrives in PR 6, so earlier PRs change no behavior.

1. **`docs: plan M2`** (this document).
   - Out: code.

2. **`feat(sys): writes through Fs`**
   - Goal: `Fs` gains `write_atomic(path, bytes, owner: FileOwner{mode,uid,gid})`, `write` (truncate in place, for `/proc/sys` only), `append_sync` (for the journal), `remove`, `create_dir_all(path, mode)`. Add the `Sys` struct. `FakeFs` becomes mutable behind a `Mutex`, keeps per-file metadata, and can fail the n-th write.
   - Files: `sys/mod.rs`, `sys/fake.rs`.
   - Tests: `RealFs` on a tempdir (content, mode, overwrite leaves no temp file, symlink target refused, a failed write leaves the original); the same assertions against `FakeFs`.
   - Out: lock, SELinux contexts, xattrs, owner changes in tests (non-root CI cannot `chown`; the call is covered on `FakeFs` and in containers).

3. **`feat(resource): File and Sysctl resources`**
   - Goal: `src/resource/` with `Resource`, `Change`, `Reversibility`, `Backup`, `restore`, `ResourceError`; the `File` and `Sysctl` kinds; unified diffs via `similar` (new dependency).
   - Tests: diff none/some; snapshot → apply → restore round trip on `FakeFs` (including a file that did not exist); `Backup` serde round trip.
   - Out: `Package`, validate, engine.

4. **`feat(engine): transactions, journal, lock and rollback`**
   - Goal: `src/engine/`:
     - `plan` over `&[&dyn Module]` (a test-only module is enough here);
     - `apply` with write-ahead journal, verify and automatic rollback;
     - `rollback` with the safety check;
     - `history` listing;
     - `TxnState` transitions;
     - state dir creation and permission check; lock; transaction IDs.
   - Tests: failure injection at every write; crash simulation (truncate the journal after each line, then `rollback --txn` restores); illegal state transitions; the safety check refuses a changed file; lock contention on a tempdir (two `try_lock`s); date helper.
   - Out: real modules, CLI.

5. **`feat(modules): kernel.sysctl`**
   - Goal: the `Module` trait, the registry, `kernel.sysctl`, `fix = "kernel.sysctl"` on the 14 controls, `fix` in `audit` output.
   - Tests: fixture idempotency and rollback, the `insta` plan snapshot, audit-and-fix agreement, never `ip_forward`/`accept_ra`/`rp_filter`, no runtime-sticky values, the property test.
   - Out: the CLI to run it (next PR).

6. **`feat(cli): plan, apply, rollback and history`**
   - Goal: the four commands, the text and JSON plan, the prompt, the root check, the lock, exit codes.
   - Tests: `insta` snapshot of the rendered plan from a fake; `assert_cmd`: `apply` without root exits 2 and changes nothing; `plan --json` parses; `rollback` without `--last` or `--txn` is a usage error.
   - Manual: a throwaway VM run of `kernel.sysctl` noted in the PR.
   - Out: `updates.auto`.

7. **`feat(modules): updates.auto`**
   - Goal: the `Package` resource (apt only; `dpkg-query` for state); `File::validate` (`apt-config -c <files/n.after> dump` must exit 0 before the real file is written); the `updates.auto` module; `fix = "updates.auto"` on `UPD-001`.
   - Tests: fixture plans (Debian 12 without the package, Ubuntu 24.04 with it); validate failure aborts before any write; container cycle added to the `containers` CI job.
   - Out: other package managers, the platform layer, timers.

8. **`chore: release v0.2.0`**
   - Goal: README command table and "today" notes, `testing.md` (what layer 2 now covers), `CONTRIBUTING.md` (adding a module), version bump.
   - Out: anything new.

## Deferred from the architecture

The architecture describes v1. For M2 these parts are not needed or are simpler:

| Architecture | M2 | When |
|---|---|---|
| Platform layer (`PkgManager`, `ServiceManager`, `Firewall`, `Sshd`) | `Package` calls apt directly; modules check `facts.os` | When a second package manager or init system is supported (M6). `Sshd` and `Firewall` in M3 |
| Profiles (TOML, `extends`, `schemars` JSON Schema), `/etc/vps-ready/config.toml` | `--module` selects modules; no parameters | M3, when `user.admin` needs keys; JSON Schema when an editor or the wizard needs it |
| Module `params`, `requires`/`conflicts` + topological sort, `validate`, `verify`, `needs_deadman` | Fixed registry order; per-file validate; generic verify | M3 (`user.admin` before `ssh`) |
| `plan --out plan.json` → `apply plan.json` with hash checks | `apply` plans under the lock and shows the plan before asking | When cloud-init export needs it (M5), if ever |
| `askama` templates | Two small generated files, built with `format!` and pinned by `insta` | M3, with the sshd drop-in |
| `meta.json`, `plan.json`, `diff.patch`, `state.json`, `/var/log/vps-ready/` | The journal is the record; logs go to stderr | `state.json` with `drift` (M6) |
| ULID transaction IDs, `rustix` for `fsync`/`flock` | UTC timestamp IDs; `std` has `sync_all`, `fchown` and `File::try_lock` | Not needed |
| SELinux context in snapshots | Mode, owner, bytes | With Rocky/Alma (M6) |
| `Service`, `User`, `AuthorizedKeys`, `FirewallRuleset` resources; reload step | Not needed by M2 modules | M3 |

## Owner decisions

These are decided above as written. Say if you want them otherwise:

1. Two modules in M2 (`kernel.sysctl`, `updates.auto`); `base.time`, `base.swap` and journald after v0.2.0.
2. `kptr_restrict=2` (the baseline's value) rather than `1`. `2` hides kernel addresses from root too, which can get in the way of `perf` for admins.
3. Rollback leaves a package that vps-ready installed in place (`partial`), rather than removing it.
4. No profile file in M2.
5. Exit code 3 for "rollback incomplete", so scripts can tell it apart from a clean rollback.
