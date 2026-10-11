# Security baseline: what a fresh VPS needs and why

This is both the **spec for the modules** and a **learning reference**. Each item has the threat it addresses, how it's done per distro, the risk of breaking something, a check command and a rollback.

> Version-sensitive facts were researched in Oct 2026. The tool must *detect* versions at runtime (`ssh -V`, `ssh -Q kex`, `/etc/os-release`) rather than hard-code them.

## 0. Platform matrix

| | Debian 12/13, Ubuntu 22.04/24.04/26.04 | Rocky/Alma 9/10, Fedora | Alpine 3.2x |
|---|---|---|---|
| Packages | apt | dnf (Fedora: dnf5) | apk |
| Init | systemd | systemd | **OpenRC** |
| Firewall | ufw (Ubuntu), nftables (Debian) | firewalld | nftables / awall |
| MAC | AppArmor | SELinux | none |
| sudo | sudo; **sudo-rs default on Ubuntu 26.04** | sudo, group `wheel` | `doas` |
| Time | timesyncd; chrony+NTS on Ubuntu 25.10+ | chronyd | chronyd |

Distro changes that break old guides:
- **OpenSSH 10.0** makes post-quantum `mlkem768x25519-sha256` the default and removes DSA.
- **Debian 13** no longer reads `/etc/sysctl.conf`; use `/etc/sysctl.d/`. `/tmp` is now tmpfs.
- **Ubuntu ≥22.10** uses `ssh.socket` activation, so port changes need `daemon-reload` + `restart ssh.socket`.
- **Rocky 10** disables root by default.

## Preflight (always runs, read-only)

1. Read the facts: OS, init, virtualization (`systemd-detect-virt`; skip kernel/sysctl/swap modules in LXC/OpenVZ), cloud-init, cloud provider.
2. Record the admin's IP from `$SSH_CONNECTION` and the **actually listening** SSH port from `ss -tlnp`.
3. Ask: *"Does your provider's web console work?"* Recommend a provider snapshot.
4. Back up `/etc/ssh`, `/etc/sudoers*`, the firewall ruleset and `sysctl -a` before anything changes.

---

## Module catalog

Legend: **Risk** = chance of lockout or breakage (L/M/H). **Profile** = M(inimal) / W(eb-docker) / P(aranoid).

### Base system

| ID | Module | Why (threat) | How | Check | Risk | Profile |
|---|---|---|---|---|---|---|
| `base.update` | Full upgrade | Known CVEs in the shipped image | `apt-get -y full-upgrade` (with `DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a`) / `dnf -y upgrade --refresh` / `apk -U upgrade` | `/var/run/reboot-required`, `dnf needs-restarting -r` | L, irreversible | MWP |
| `base.time` | UTC + NTP (chrony) | Wrong time breaks TLS, TOTP, log correlation | `timedatectl set-timezone UTC`; chrony; NTS needs **outbound TCP 4460** | `timedatectl`, `chronyc tracking` | L | MWP |
| `base.hostname` | Hostname | Clarity; `sudo` warns when `/etc/hosts` is wrong | `hostnamectl` + `/etc/hosts` + cloud-init `preserve_hostname: true` | `hostnamectl` | L | MWP |
| `base.swap` | Swapfile (RAM ≤ 2 GB) | Out-of-memory kills during builds / `apt` | `fallocate`, `mkswap`, fstab, `vm.swappiness=10` (Btrfs: `btrfs filesystem mkswapfile`) | `swapon --show` | L | MW |

### Accounts

| ID | Module | Why | How | Check | Risk |
|---|---|---|---|---|---|
| `user.admin` | Non-root sudo user + key | Root is the universal brute-force target; gives an audit trail per human | `adduser`/`useradd -G wheel`; copy `authorized_keys` with `0700`/`0600`; **`restorecon -Rv ~/.ssh` on SELinux** | `id admin`, `sudo -l -U admin` | **M**: a passwordless user + sudo that requires a password = no root. Decide NOPASSWD vs set a password; `visudo -cf` |
| `user.lock` | Lock unused login accounts | Dormant accounts are a backdoor | `usermod -L -s /usr/sbin/nologin` | `passwd -S` | L |
| `user.pwpolicy` | pwquality (console/sudo only) | Weak local passwords | `/etc/security/pwquality.conf minlen=14` | | L. **Avoid** password expiry (it blocks key logins, dev-sec #681) |

### SSH (highest lockout risk; the dead-man switch is required)

**Mechanism:** write **one** drop-in, `/etc/ssh/sshd_config.d/00-vpsready.conf`.
- sshd uses the **first value it reads** for each keyword, and the `Include` is at the top of `sshd_config`.
- So `00-` beats cloud-init's `50-cloud-init.conf` (which sets `PasswordAuthentication yes`).
- Also write `/etc/cloud/cloud.cfg.d/99-vpsready.cfg` containing `ssh_pwauth: false` so cloud-init doesn't write it back.
- If there's no `Include` line (check Alpine/Arch), add one as the first line.

```sshconfig
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3              # tip: tell users to set IdentitiesOnly in ~/.ssh/config
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
PermitUserEnvironment no
LogLevel VERBOSE            # logs key fingerprints
AllowGroups sshusers        # add admin + deploy to the group FIRST
```

**Crypto:** *subtract* from the defaults rather than pinning lists, which go stale. Build the list from `ssh -Q kex`.
- Use `^mlkem768x25519-sha256,…` to prefer post-quantum KEX, and `-ecdh-sha2-*` style removals.
- Set `RequiredRSASize 3072`.
- **On RHEL-likes don't set Ciphers/KEX/MACs in sshd**: it silently overrides crypto-policies. Use `update-crypto-policies --set DEFAULT:NO-SHA1` (or `FUTURE` for paranoid).

**Port change: keep 22 by default.** Changing it only reduces log noise. It touches five places that can each lock you out: the firewall, the provider firewall, the SELinux `semanage port`, `ssh.socket` and fail2ban. A private network (Tailscale) is the real fix.

**Validate before reload:** `sshd -t` → `sshd -T | grep -Ei 'passwordauth|permitroot|kbdinter'` → `sshd -T -C user=admin,host=x,addr=1.2.3.4` (for Match/AllowGroups). Then `reload`; existing sessions survive it.

**Second factor (opt-in):**
- **FIDO2 `ed25519-sk` keys with `verify-required`** (recommended; phishing-resistant).
- Or TOTP via `pam_google_authenticator` + `AuthenticationMethods publickey,keyboard-interactive:pam`.

### Firewall

**Policy:** deny inbound, allow outbound, allow established/loopback/ICMP. **Never block ICMPv6** (neighbour discovery and path-MTU discovery need it). **Allow SSH before enabling.**

| Family | How | Safety net |
|---|---|---|
| Ubuntu (ufw) | `ufw default deny incoming; ufw limit 22/tcp; ufw allow 80,443/tcp; ufw allow 443/udp; ufw --force enable` | dead-man switch → `ufw disable` |
| RHEL (firewalld) | Apply **runtime-only** first, confirm, then `--runtime-to-permanent` | Reloading or rebooting reverts by itself |
| Debian/Alpine (nftables) | Write `/etc/nftables.conf` → `nft -c -f` → `nft -f` | Keep the previous ruleset file for a one-shot restore |

**Warning: Docker bypasses ufw/firewalld.** Published ports are NATed before INPUT. Mitigations, best first:
1. `"ip": "127.0.0.1"` in `daemon.json` so ports default to loopback, with the reverse proxy as the only public entry.
2. `DOCKER-USER` chain rules (the ufw-docker approach).
3. The provider firewall.

Also: `ufw reset` / `nft flush ruleset` deletes Docker's chains, so run `systemctl restart docker` afterwards.

**Check from outside:** `nmap -Pn -p- <ip>` and `nmap -6 …`.

### Brute-force protection

| Option | Use when |
|---|---|
| OpenSSH **PerSourcePenalties** (9.8+, on by default) | Minimal profile; nothing to install |
| **fail2ban** | Simple, single host. On Debian 12+ **must** set `backend = systemd` + install `python3-systemd` (there's no `auth.log` by default) + `banaction = nftables-multiport`. `ignoreip` = admin IP |
| **CrowdSec** + firewall bouncer | Web host; also parses nginx/Caddy logs; shared blocklist (privacy trade-off) |
| sshguard | Alpine / tiny boxes |

Once SSH is key-only, brute force is mostly noise. Don't oversell this module.

### Automatic security updates

| Family | How |
|---|---|
| Debian/Ubuntu | `unattended-upgrades`, `20auto-upgrades`, our `52vpsready` drop-in: `Automatic-Reboot "false"` (or a reboot window), `Remove-Unused-Kernel-Packages "true"`. **Leave Docker's repo out** (an upgrade restarts containers unless `live-restore` is on) |
| RHEL 9/10 | `dnf-automatic`, `upgrade_type = security`, `apply_updates = yes`, timer |
| Fedora 41+ | `dnf5-plugin-automatic` |
| Alpine | `/etc/periodic/daily/apk-upgrade`; warn when the branch nears end of life |

Also make sure **needrestart ≥ 3.8**, because older versions have local-root CVEs (CVE-2024-48990 family).

### Kernel / sysctl (`/etc/sysctl.d/90-vpsready.conf`)

**Safe set (all profiles):**
- no ICMP redirects or source routing, `tcp_syncookies=1`;
- `rp_filter=2` (loose: `1` breaks Tailscale routing);
- `kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `yama.ptrace_scope=1`;
- `fs.protected_*`, `fs.suid_dumpable=0`.

**Never set:**
- `net.ipv4.ip_forward=0`: kills Docker, k8s and Tailscale (dev-sec ships this, and it's their #1 Docker complaint).
- `accept_ra=0`: drops SLAAC IPv6 on many providers. Docker hosts with SLAAC need `accept_ra=2`.

**Paranoid only:** `kexec_load_disabled`, `sysrq=0`, `perf_event_paranoid=3`. `unprivileged_userns_clone=0` breaks rootless containers.

### Logging and auditing

- **journald:** `Storage=persistent`, `SystemMaxUse=1G`, `SystemKeepFree=2G`, `MaxRetentionSec=3month`.
- **auditd** (W: basic, P: full): watches on passwd/shadow/sudoers/sshd_config/cron/`/root/.ssh` + root execve by real users. Paranoid adds `-e 2` (immutable rules).
- **Remote logs** (P): Vector / Fluent Bit / Alloy / `systemd-journal-upload`. Logs that leave the box survive an attacker wiping them.

### Integrity / MAC / filesystem

- **Lynis** as an optional external audit. **AIDE** in paranoid only, and only useful if the database is kept off-host. **rkhunter: legacy, off.**
- **AppArmor/SELinux:** must be enforcing. Report it, and never disable it to "fix" something.
- **/tmp:** `nosuid,nodev` by default. `noexec` is paranoid only, because it breaks pip/rustup/apt scripts.
- Core dumps off; `umask 022` (027 breaks reverse-proxy reads).
- **Listening services:** the real check is `ss -tulpn`. Mask `rpcbind`, `avahi`, `cups` if present; keep MTAs on loopback.

### Deployment readiness

| ID | Module | Key points |
|---|---|---|
| `deploy.docker` | Docker Engine from the **official repo** | `daemon.json`: `log-driver local` with size limits, `live-restore`, `no-new-privileges`, `userland-proxy:false`, `ip:127.0.0.1`. **The docker group is equivalent to root.** Rootless/Podman as an option |
| `deploy.user` | `deploy` user | No general sudo; `sudoers` allows only `/usr/local/bin/deploy-app`; restricted `authorized_keys` (`restrict,command="…"`) for CI |
| `deploy.proxy` | Reverse proxy | **Caddy** by default (auto HTTPS); Nginx+certbot as an option; Traefik only behind a docker-socket proxy |
| `net.tailscale` | Private admin access | `tailscale up`, allow on `tailscale0`, **then close public 22 as the very last step**, behind its own dead-man switch |
| `ops.backup` | restic → S3/B2/SFTP | systemd timer, `forget --prune`, weekly `check`, DB dumps, healthchecks.io ping. *Provider snapshots aren't backups* |
| `ops.monitor` | node_exporter / Beszel | Bind to localhost or the tailnet. **Netdata listens publicly on :19999 by default** |

---

## Safe order of operations (what the engine enforces)

0. Preflight + backups + snapshot advice.
1. Update, time, hostname, swap.
2. Admin user + key + sudo → **Challenge 1:** the user opens a *new* terminal and runs `ssh admin@host sudo vpsready confirm <code>`. This proves a fresh login with the right user, key and sudo all work. Nothing restrictive runs before it.
3. SSH drop-in: write → `sshd -t` → `sshd -T` effective check → **arm dead-man** → reload → **Challenge 2** from a new connection → disarm.
4. Firewall: allow current SSH + admin IP → arm dead-man → enable → confirm from a new connection.
5. Brute-force protection, updates, sysctl, journald, auditd.
6. Deployment modules.
7. Tailscale → confirm SSH over tailnet → close public 22 (dead-man).
8. Reboot → re-audit → report.

> **Why a *new* connection?** sshd reloads and conntrack keep *existing* sessions alive. Your open terminal proves nothing.

## Profiles

| | Minimal | Web / Docker host | Paranoid |
|---|---|---|---|
| Base (update, time, hostname, swap) | ✓ | ✓ | ✓ |
| Admin user, root off, SSH drop-in | ✓ | ✓ | ✓ + FIDO2/TOTP, no TCP forwarding |
| Firewall | SSH only | SSH, 80, 443 tcp+udp, Docker-safe | SSH via tailnet only |
| Brute force | PerSourcePenalties | CrowdSec or fail2ban | CrowdSec on proxy |
| Auto updates | security, no reboot | security + reboot window, Docker excluded | + auto reboot / livepatch |
| sysctl | safe | safe, forwarding on, accept_ra=2 | + paranoid keys |
| journald / auditd | yes / no | ✓ / basic | ✓ + remote / full + immutable |
| Docker, proxy, deploy user, backups | no | yes | yes (rootless preferred) |
| Tailscale + close 22 | offered | recommended | required |

## Top 10 gotchas (each needs a test)

1. cloud-init `50-cloud-init.conf` re-enables passwords → `00-` drop-in + `ssh_pwauth: false` + verify with `sshd -T`.
2. Ubuntu `ssh.socket` ignores the port change → `daemon-reload` + `restart ssh.socket`.
3. SELinux: wrong `.ssh` labels / unlabeled port → `restorecon`, `semanage port`.
4. Firewall enabled before SSH is allowed; IPv6 forgotten; provider firewall forgotten.
5. Passwordless admin + password-required sudo + root disabled = no root.
6. `AllowGroups` leaves out the admin/deploy user → check with `sshd -T -C user=…`.
7. `MaxAuthTries 3` + many agent keys → "Too many authentication failures" → print an `IdentitiesOnly` tip.
8. Docker bypasses the firewall / a firewall reset wipes Docker chains / `ip_forward=0` kills containers.
9. `accept_ra=0` drops IPv6; `rp_filter=1` breaks Tailscale; Debian 13 ignores `sysctl.conf`.
10. Unattended reboots, Docker upgrades and needrestart restarts interrupt services → reboot window, `live-restore`, exclude Docker's repo.

## Compliance mapping (not compliance claims)

- Internal control IDs (e.g. `SSH-002`) carry references: ComplianceAsCode rule IDs (`sshd_disable_root_login`), CIS section numbers per benchmark version, Lynis test IDs (`SSH-7408`).
- We ship **IDs only, never CIS text** (licensing).
- For formal reports, hand off to `usg` / `oscap`.
