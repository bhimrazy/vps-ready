---
title: Introduction
description: vps-ready audits a fresh Linux server and hardens it, with a plan you review first, a journal you can undo, and a safety net that rolls back SSH and firewall changes that cut off your access.
---

vps-ready is one static binary that audits a fresh Linux server and hardens it, with a plan you review first and a one-command undo after. Its headline feature is the safety net: before it keeps a change to SSH or the firewall, it proves you can still log in.

:::note
vps-ready is pre-1.0. `detect` and `audit` (29 controls), and `plan`, `apply`, `confirm` and `rollback` for six modules work today on Debian 12/13 and Ubuntu 22.04/24.04 with systemd. There may be breaking changes before 1.0.
:::

## Why

You buy a VPS, get `root@ip`, and want to deploy something. Before that you should do about fifteen setup steps: an admin user with an SSH key, SSH hardening, a firewall that also covers Docker, automatic security updates, sane kernel settings, logging. In practice people follow an old blog post, run a random script as root, lock themselves out of SSH, or end up with a firewall that silently ignores their containers.

Auditors like Lynis tell you what is wrong but fix nothing. Ansible roles fix things but need a control machine and offer no undo. vps-ready combines the useful parts into one tool.

## Commands

| Command | What happens |
|---|---|
| `vps-ready detect` | Read-only facts: distro, init system, virtualization, effective SSH server config, listening ports, whether Docker is present |
| `vps-ready audit` | Checks the server against controls with stable IDs (for example `SSH-002`), each with the reason it matters. Text or JSON; exits 0 only when no control fails or is unknown |
| `vps-ready plan` | A diff of every file and setting that would change, with a one-line reason for each |
| `vps-ready apply` | Snapshots originals, validates, writes atomically and rolls back if anything fails. SSH and firewall changes start the safety timer first and wait for a confirm |
| `vps-ready confirm` | Run from a **new** SSH login, as the admin user, to prove the new configuration works. Without it, the changes roll back on their own |
| `vps-ready rollback` | Undoes a transaction from the journal (`--last` or `--txn ID`); `vps-ready history` lists transactions |

The command is also installed as `vpsready`, without the hyphen.

## Modules

| Module | What it does | Safety timer |
|---|---|---|
| `user.admin` | An admin user other than root, with your SSH keys and sudo | yes |
| `ssh.server` | One drop-in that turns off root and password logins and the other failing settings, then reloads the SSH server | yes |
| `firewall.inbound` | Drops unsolicited inbound traffic in vps-ready's own nftables table, always allowing every current SSH port | yes |
| `ssh.bruteforce` | fail2ban, banning addresses that keep failing to log in over SSH | no |
| `kernel.sysctl` | Safer kernel and network settings | no |
| `updates.auto` | Automatic security updates with `unattended-upgrades` | no |

Profiles pick the modules: **minimal** is `user.admin`, `ssh.server`, `firewall.inbound` (SSH only), `kernel.sysctl` and `updates.auto`; **web** adds ports 80 and 443 and `ssh.bruteforce` (fail2ban). A plain `apply`, without `--profile` or `--module`, changes only kernel settings and automatic updates.

## Safety guarantees

- **Never lock you out.** Root and password login stay on until an admin user with SSH keys and sudo exists, checked against the live SSH server config. The firewall always allows the SSH port that is actually in use.
- **Confirm from a new login.** The safety timer (5 minutes by default) rolls back the admin user, SSH and firewall changes unless a new SSH login runs `vps-ready confirm` in time, even if the tool or the terminal is gone, and even if the server reboots.
- **Show, then do.** Nothing changes without a plan you can read. Every change carries a reversibility label.
- **Effective state over file state.** Controls are checked with `sshd -T`, `/proc/sys`, `apt-config`, `nft` and `ss`.
- **Drop-ins, not edits.** The tool owns its own files and never rewrites your `sshd_config` in place.
- **No network calls** except package installs. No telemetry, no self-update.

The full list and its reasoning are in [Security controls](/docs/guides/security-controls/) and [Architecture](/docs/guides/architecture/).

## Supported platforms

| Family | Distros | Status |
|---|---|---|
| Debian | Ubuntu 22.04, 24.04; Debian 12, 13 | since v0.2 |
| RHEL | Rocky and Alma 9, 10; Fedora | v0.6 |
| Alpine | 3.2x | v0.6 |

Architectures: x86_64 and arm64 (aarch64), as static musl binaries. Windows, BSD, Kubernetes nodes and fleet management are out of scope.

## Next steps

- [Install](/docs/install/) vps-ready on a server.
- Follow the [Quick start](/docs/quick-start/) from audit to confirm.
