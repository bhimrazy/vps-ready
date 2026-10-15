# Vision, scope and prior art

## Problem

Someone buys a $5 VPS, gets `root@ip` access with a password or one key, and wants to deploy an app. Before that they *should* do roughly 15 setup things (see [the security baseline](security-baseline.md)). In practice they:

- follow a blog post from 2019 that conflicts with today's distro defaults (cloud-init drop-ins, `ssh.socket`, Debian 13 ignoring `/etc/sysctl.conf`);
- run a random `curl | bash` script as root, without reading it;
- lock themselves out of SSH, or
- end up with a firewall that silently doesn't apply to Docker containers.

## Looking at it from different angles

| Perspective | What they need | Implication for the tool |
|---|---|---|
| **Beginner / indie dev** | "Make it safe, don't make me read 40 pages" | One recommended profile, plain-English explanations, impossible to lock yourself out |
| **Intermediate sysadmin** | Control and understanding | Every change shown as a diff with a *why*, toggles per module, undo |
| **Senior / SRE** | Automation, auditability | Non-interactive TOML profile, JSON/SARIF output, exit codes, cloud-init export, readable code |
| **Security reviewer** | Trust the binary that runs as root | Signed, reproducible builds, small dependency tree, no telemetry, no self-update |
| **Attacker** | Weak SSH, exposed services, stale packages, Docker bypassing the firewall | These are the default modules, ordered by real-world impact rather than checklist length |
| **Hosting provider / panel** (Coolify, Dokploy) | Something embeddable before or after their own install | Permissive license, stable CLI, Docker-aware firewalling |
| **Contributor** | Easy to add a module safely | Modules are small and declarative; the engine owns the dangerous parts; there's a per-distro test matrix |
| **Maintainer (future you)** | Not drown in distro quirks | Distro differences are data tables plus platform adapters, never `if ubuntu` scattered in modules |

## Prior art: what already exists (Oct 2026)

> Summary only.

| Category | Examples | Good at | Missing |
|---|---|---|---|
| **Auditors** | Lynis (16k★), OpenSCAP/SSG, Ubuntu USG, ssh-audit, docker-bench, Goss | Mature checks, stable test IDs | Don't fix anything; output assumes an expert reader |
| **Ansible remediators** | dev-sec hardening (5.5k★), ansible-lockdown CIS, geerlingguy roles | Idempotent, CIS-mapped, well tested | Need Python/Ansible + a control node; not interactive; no rollback; aimed at fleets |
| **Bash "first hour" scripts** | du_setup (~800★), koncreet, Fortis, dozens of clones | The right UX (interactive, Docker, Tailscale) | Debian/Ubuntu only, hard to verify, weak dry-run, single maintainer; konstruktoid/hardening is now "not idempotent, unmaintained" |
| **Go/Rust single binaries** | hostveil, hardbox, postlab | Exactly this architecture | Almost no adoption (2 to 64 stars); GPL/AGPL; audit-first rather than provisioning-first |
| **Panels / SaaS** | Laravel Forge, Ploi, RunCloud; Coolify/Dokploy | Forge has a good invisible baseline | Coolify's docs explicitly leave host hardening to you, and it uses root SSH by default |
| **Guides** | How-To-Secure-A-Linux-Server (32k★) | Teaching | Not a tool |

**The honest conclusion:** every *individual* feature already exists somewhere. What's missing is one **trusted** tool that combines them. The way to win is quality and safety, not novelty. Otherwise this becomes the 30th "vps-harden" repo.

## Our wedge (what makes this worth building)

1. **Provisioning-first.** The first 10 minutes after `ssh root@new-vps`, *plus* deployment readiness: deploy user, Docker done right, reverse proxy, backups, Tailscale.
2. **Provably lockout-safe.** This is the headline feature:
   - Refuse to disable passwords until a keyed sudo user has been *proven* to work from a new session.
   - Check the *effective* config (`sshd -T`), not file contents.
   - Allow the current SSH port in the firewall before enabling it.
   - A dead-man switch auto-reverts unless the user confirms from a **new** SSH connection.
3. **Detection that matters.** Cloud provider quirks:
   - cloud-init drop-ins (DO/Hetzner);
   - Oracle's baked-in iptables rules;
   - AWS IMDS must stay reachable;
   - GCP's guest agent manages users.

   Also: LXC vs VM, `ssh.socket` vs `ssh.service`, Docker present or not.
4. **Plan → apply → verify → rollback** with Terraform-style diffs and honest reversibility labels: *reversible*, *partial*, *irreversible*.
5. **Audit and fix share one rule definition.** Stable IDs, cross-referenced to CIS / Lynis / ComplianceAsCode IDs. We map to CIS; we don't claim CIS compliance.
6. **Export:** use it interactively once, then export the profile as cloud-init `user-data` for the next 50 servers.
7. **Trust:** signed and reproducible releases, apt/rpm/apk packages, no `curl | bash` *required*.

## Principles

1. **Never lock the user out.** Every risky step is gated, validated and reversible with a timer.
2. **Show, then do.** Nothing changes without a visible plan (except with `--yes`).
3. **Explain why.** Every check has a one-line rationale and a "learn more" link.
4. **Prefer drop-ins over edits.** We own `00-vps-ready.conf` files and never rewrite `sshd_config` in place.
5. **Effective state over file state.** Check with `sshd -T`, `/proc/sys`, `apt-config` and `ss`.
6. **Small and boring beats broad.** A perfect core of 10 modules beats 21 untested ones.
7. **No network calls except package installs.** No telemetry and no phoning home.

## Non-goals (for v1)

- Full CIS Level 2 / STIG compliance (USG and ansible-lockdown own that; we map IDs only).
- Fleet management or a central server (export to cloud-init/Ansible instead).
- A web UI.
- Managing applications after deploy (that's Coolify/Dokploy/Kamal territory).
- Kubernetes node hardening (kube-bench exists).
- Windows/BSD.

## Threat model of the tool itself

The tool runs as root on a fresh box, so we must think about how *it* could hurt users:

| Threat | Mitigation |
|---|---|
| Malicious or compromised release binary | Cosign keyless signatures, SLSA provenance (L2 today, L3 the target), immutable GitHub releases, reproducible builds ([the release doc](release.md)) |
| Compromised install script | Script generated per release with hashes embedded; recommend download → read → run |
| Compromised dependency | Small allowlist of crates, `cargo-deny` + `cargo-audit` (RustSec) in CI, Dependabot with a `cooldown` period, 2-maintainer CODEOWNERS on critical paths (once there are two maintainers) |
| The tool locks the user out (availability) | Invariants plus dead-man switch plus VM tests of the revert path |
| The tool *weakens* security by mistake (e.g. a firewall rule that's too open) | Post-apply audit re-runs every control; snapshot tests (`insta`) of rendered configs |
| Secrets leaking in logs or backups | Backups in `/var/lib/vps-ready` with mode `0700`; never log private key material; redact tokens (e.g. Tailscale auth keys) |
| Local privilege escalation via tool state files | Root-owned state; refuse to run if state dir permissions are wrong; atomic writes; no world-writable temp files |
