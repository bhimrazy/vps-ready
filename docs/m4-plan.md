# M4 plan: the guided wizard (v0.4.0)

M4 makes `sudo vps-ready` with no arguments a short guided setup for someone who has never hardened a server: it looks at the host, recommends a profile, asks three or four questions, shows the plan, applies it with the safety timer, and ends by printing the command that does the same thing without questions. It also adds `vps-ready modules`, which explains each module.

The wizard is a front end, not a new path: it builds a profile and hands it to the same `plan` and `apply` code the commands use. Anything it does, `apply --profile <file>` can repeat. The engine, the modules and the safety timer do not change.

Debian 12/13 and Ubuntu 22.04/24.04 with systemd, as in M3.

## Decisions

### Entry point

`Cli.command` becomes `Option<Command>`. With no subcommand, `vps-ready` starts the wizard when stdin and stdout are both terminals. Otherwise it behaves as today (help on stderr, exit code 2), so scripts and pipes see no change. There is no `wizard` subcommand: the bare command is the one the README and the site teach.

Before the first question, in this order, the wizard stops with the same message the commands print:
1. Not root: `Run it with sudo: sudo vps-ready`. `vps-ready plan` stays the way to look without root.
2. The binary cannot be trusted to run from the safety timer (the existing binary-path check, for example `./vps-ready` in a home directory).
3. A transaction is pending or did not finish: the engine's own message (`rollback --txn ID`, or wait for its deadline). This takes the lock, as `apply` does.

So nobody answers every question and then fails at apply for a reason that was known at the start.

### The flow

```
$ sudo vps-ready
vps-ready 0.4.0 on Ubuntu 24.04 (KVM)
Audit: 25 passed, 3 failed (2 medium, 1 low). vps-ready can fix 2 of them.

? What will this server run?
  > Web apps or Docker: opens 80 and 443 (recommended: Docker is installed)
    Something else: SSH only
? Admin user: alice   (existing account, the one you logged in as)
? Open ports besides SSH (22): [x] 80/tcp  [x] 443/tcp  [x] 443/udp  [ ] 5432/tcp (postgres)
? Change the module list? (y/N)

<the plan, exactly as `apply` prints it>
Apply 9 changes? [y/N] y
...
<the safety timer countdown and the confirm line, as today>

Next time, without questions:
  sudo vps-ready apply --profile web
```

1. **Header and audit line.** The OS line from `detect` and the audit summary, so the questions have a reason. One line each, no list.
2. **What will this server run?** Two choices that map to the built-in profiles, `web` and `minimal`. The recommended one is first and says why: `web` when Docker is installed or something listens publicly on 80 or 443, else `minimal`.
3. **Admin user.** The default follows the rule `ssh.server` already uses: the user this SSH session logged in as when that is not root, else `admin`. Naming the session user is always safe: `user.admin` only adds (keys are appended, an existing password is never touched, existing sudo rules are kept). The line under the question says what will happen to the name typed, checked with the same lookups `user.admin` uses:
   - a new account: `created, with N keys from <path>`;
   - an existing login account: `existing account: gets sudo and N keys from <path>`, so granting sudo to an existing user is never silent;
   - a name `user.admin` refuses (root, a group without a user, a system or nologin account): the refusal text, and the question is asked again.

   Keys come from where `user.admin` takes them today: the session user's `authorized_keys`, else root's, skipping lines with options (the wizard calls the module's own key reader, made `pub(crate)`, rather than a copy). When that finds no key, the wizard asks for a public key to paste, checks it with the same line check, and puts it in `authorized_keys`; it never continues without a key.
4. **Open ports.** A multi-select. The profile's ports are checked. Ports something listens on publicly are listed unchecked with the process name, under the line "Unchecked ports will be blocked." Public means a wildcard address (`*`, `0.0.0.0`, `::`) or a specific non-loopback one, with any `%zone` stripped; loopback (`127.0.0.0/8`, `::1`, `::ffff:127.x`), the SSH ports and ports already in the list are left out. `docker-proxy` listeners are left out too: Docker's published ports are forwarded past this firewall (see the `FW-002` control), so the line would be false for them. Under socket activation the process may show as `systemd`; it is listed as such. Another port can be typed as `<port>/tcp` or `<port>/udp`, with the same parser the profile uses, asking again on a bad value. The SSH ports are shown as always open. Asked only when `firewall.inbound` applies; otherwise the wizard says why it is skipped (for example, ufw is active).
5. **Change the module list?** Default no, matching [decisions.md](decisions.md) ("recommended by default, with Customize one keypress away"). Yes shows a multi-select of every module with its title; modules that arm the safety timer say so, and modules that do not apply are shown greyed out with the reason. Removing `user.admin` while keeping `ssh.server` works only when the host already has a keyed sudo user, which is the existing `ssh.server` rule; if not, its refusal is shown and the list is asked again.
6. **Plan and apply.** `cli/change.rs` is split so the loading of `--profile` is separate from the work: `plan_profile` and `apply_profile` take an `Option<Profile>`, and the commands become a load plus a call. The wizard calls `apply_profile` with the profile it built, `yes = false` and the terminal as input, so the plan, the `Apply N changes? [y/N]` question, the progress lines, the countdown and the confirm instructions are the ones `apply` already prints. The wizard locks stdin for that answer only after its last `dialoguer` prompt, since both read the same terminal. The safety window is the default 5 minutes. "No" ends with "Nothing was changed." An empty plan ends with "Nothing to do: this server already matches." (`apply` collects the facts again; that costs about a second and keeps one code path.)
7. **Next time.** When the answers equal a built-in profile, the line is `sudo vps-ready apply --profile web` (or `minimal`). Otherwise the wizard writes the profile it built to `vps-ready.toml` in the current directory (it asks first, default yes, and never overwrites without asking) and prints the command with the file's absolute path, since `sudo` often runs in `/root`. The saved file `extends` the built-in profile and holds only what differs, with `enabled = false` for a module taken out.

Ctrl-C at any question exits with code 130 and "Nothing was changed." Ctrl-C during apply behaves as it does today.

### Prompt library: `dialoguer`, not `inquire`

The architecture doc names `inquire`. M4 uses `dialoguer` instead, with default features off and only `Select`, `MultiSelect`, `Input` and `Confirm`:
- Its terminal layer is `console`, which is small and already reviewed (it is in `Cargo.lock` today as a test dependency of `insta`, and becomes a runtime one). `inquire` brings `crossterm` and a larger tree, which matters for a static binary people pipe into `sudo sh`.
- It is from console-rs (the `insta` and `indicatif` maintainers) and widely used.
- The wizard needs four plain widgets.

The version added is one released at least 7 days before, as for every dependency. All prompts go through a small `Prompt` trait (`select`, `multi_select`, `input`, `confirm`), with a `dialoguer` implementation and a scripted one for tests. Nothing outside `src/tui/` touches `dialoguer`.

`--no-color` and `NO_COLOR` turn the theme's colors off, as they do for the rest of the output.

### Writing profiles back as TOML

`Profile` keeps neither `extends` nor disabled modules, so a `ProfileBuilder` holds the base name, the params set and the modules taken out. It builds the `Profile` the wizard applies and writes the TOML (`schema`, `extends`, only the sections that differ, `enabled = false` for removed modules). It needs the `toml` crate's `display` feature; params are already `toml::Table`, so no params struct needs `Serialize`. Merging is key by key, one level deep, so a section holding only the changed keys gives the same result. A round-trip test holds the rule: for every wizard outcome in the tests, `Profile::parse(builder.to_toml()) == builder.build()`.

### `vps-ready modules [ID]`

Replaces `modules --explain ID` from the architecture doc, since one positional argument is simpler.
- `vps-ready modules` lists every module: ID, title, whether it applies on this host (with the reason when not), and whether it arms the safety timer.
- `vps-ready modules ssh.server` adds the `why()` text, the params with their defaults and a one-line help each, the audit controls whose `fix` names the module, and the files and services it touches.
- `--json` for both. No root needed; applicability uses the same facts as `detect`.

Each module gains `params_doc() -> &'static [ParamDoc]` (name, default, help); modules without params return an empty list. A test checks that every documented param name is a field the module's params accept, so the help cannot drift from the code.

### Not in M4

| Planned before | M4 | When |
|---|---|---|
| `ratatui` plan/diff view | The plan text `apply` prints | If the plain plan proves hard to read |
| JSON Schema for profiles (`schemars`) | Strict parsing with field names in errors | With `/etc/vps-ready/config.toml` and `drift` (M6), when there is an editor-facing file to complete |
| Export as cloud-init `user-data` | The "next time" command and saved profile | M5, with `--deadman=off` for unattended runs |
| Changing the safety window in the wizard | Default 5 minutes; `apply --deadman` for other values | If asked for |
| More questions (SSH port, sysctl choices) | Three or four questions | Only with a module that needs them |

## Testing

**Layer 1:**
- The wizard flow on `FakeFs`/`FakeRunner` facts with the scripted `Prompt`, as `insta` snapshots of the full transcript:
  - a Docker host (recommends `web`; a `docker-proxy` listener is not offered);
  - a host with nothing listening (recommends `minimal`);
  - a non-root session user as admin (existing account: the plan has no `user.admin` account changes beyond sudo and keys it lacks);
  - root login, with an existing `admin` login account (says so), then with a group `admin` and no user (refused, asked again);
  - root with no keys (asks for a key; rejects a bad line, then accepts a good one);
  - a public listener on 5432 left unchecked; a bad typed port, then a good one;
  - a customized module list (writes `vps-ready.toml`, prints its absolute path);
  - not root, an untrusted binary path, a pending transaction (each stops before the first question);
  - firewall not applicable (skips the ports question).
- For every scenario that applies: the profile the wizard built, saved and parsed again, gives the same plan as the wizard's (the "anything it does, `apply --profile` can repeat" rule).
- `ProfileBuilder` and `to_toml` round trips; `params_doc` matches the params structs.
- `modules` and `modules <ID>` snapshots, text and JSON.
- Bare `vps-ready` without a terminal: help on stderr, exit code 2 (the existing test, kept).

**Layer 2 (containers):** none new; the wizard adds no system change of its own.

**Layer 3 (VMs):** cycle 7 drives `sudo vps-ready` over a real terminal with `expect` (installed in the test VM only) on all four images, then checks that `vps-ready apply --profile <printed>` plans no changes:
- logged in as the image's cloud user: accept the defaults (the session user becomes the admin), apply, confirm from a second SSH session;
- logged in as root with a key (the seed already adds one): accept the defaults (creates `admin` with root's key), apply, confirm as `admin` from a second session.

## PR sequence

1. **`docs: plan M4`** (this document).
2. **`feat(cli): modules`**: `modules` and `modules <ID>`, `params_doc` on every module. *Parallel with 3.*
3. **`feat(config): profile builder, TOML output and apply_profile`**: `ProfileBuilder`, `to_toml`, the `toml` `display` feature, round-trip tests; `plan_profile`/`apply_profile` split out of `cli/change.rs` with no change in behavior; `user.admin`'s key reader and line check made `pub(crate)`. *Parallel with 2.*
4. **`feat(tui): the wizard`** (needs 3): `src/tui/` with the `Prompt` trait and its `dialoguer` implementation, `Option<Command>`, the start checks, the flow above, the "next time" line and `vps-ready.toml`, the layer 1 scenarios.
5. **`test(vm): wizard cycle`** (needs 4): cycle 7.
6. **`docs(site): the wizard`** (needs 4): README quick start leads with `sudo vps-ready`; the site's quick start and install pages; the landing page's wizard preview (now "Design preview") replaced by real output; `architecture.md` (`dialoguer`, `modules <ID>`, `src/tui`), `decisions.md` (the default-profile question decided).
7. **`chore: release v0.4.0`**: version bump, milestone, release notes.

Waves: {2, 3} → 4 → {5, 6} → 7.

## Decided by the owner (2026-10-31)

All eight recommendations were accepted:

1. **`dialoguer` instead of `inquire`.** Recommended for the smaller dependency tree (see above).
2. **Bare `vps-ready` is the wizard on a terminal** and help otherwise, with no `wizard` subcommand.
3. **Root, the binary check and a pending transaction are checked before the first question**, rather than failing at apply.
4. **Customized answers are saved to `vps-ready.toml`** (asked, default yes), rather than only printed.
5. **Paste a key when none is found**, rather than stopping with instructions.
6. **Public listeners are offered unchecked**, with "Unchecked ports will be blocked" (Docker's published ports left out, since this firewall does not filter them), rather than checked. Checked would keep a running service reachable but could expose a database.
7. **`modules <ID>`** instead of `modules --explain <ID>`.
8. **JSON Schema and `ratatui` wait** (see Not in M4), although the architecture doc tied the schema to M4.
