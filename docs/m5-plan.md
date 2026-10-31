# M5 plan: deployment readiness (v0.5.0)

> **Status: accepted.** Nothing below is built yet. The owner decided the open questions on 2026-10-31 (see the end).

M5 takes a server that M3 and M4 hardened and gets it ready to run an app: Docker installed with safe defaults, a reverse proxy with automatic HTTPS, a deploy user for CI, and a way to install vps-ready itself as a package. The milestone as written also had Tailscale with public port 22 closed, and a cloud-init export. Those two change the safety model (a confirm that must arrive over the tailnet, and an apply with no one to confirm at all), so this plan moves them to a second release, v0.6.0, where they get their own design and VM time.

The engine, the journal and the safety timer stay as they are, apart from two new reloads. Each new module is an ordinary module: it plans resources, `apply` journals them, and `rollback` undoes them.

Debian 12/13 and Ubuntu 22.04/24.04 with systemd, as in M4.

## Decisions

### Scope: two releases

| Release | Contents |
|---|---|
| **v0.5.0 (M5)** | `deploy.docker` (with the `FW-002` fix), `deploy.proxy` (Caddy), `deploy.user`, vendor apt sources, a `.deb` package, an SBOM |
| **v0.6.0 (M5, part 2)** | `net.tailscale` and closing public 22, `apply --deadman=off\|selftest`, `export cloud-init` |

None of the v0.5.0 modules touches sshd, the firewall's SSH rule or the admin's login, so they do not arm the safety timer. They cannot lock out an admin who logs in through the host's own sshd. They can stop containers (see the Docker restart below), which matters only to someone who reaches the host through a container, and the plan says when that will happen. The v0.6.0 items all change the SSH path or turn the timer off, so they are reviewed together as one change to the safety model.

### Vendor apt sources

Docker and Caddy (and later Tailscale) install from their vendor's apt repository. Today `Package` installs only from the distro's repositories, and nothing writes a repository or a key. A helper, `apt_source(name, key, uri, suite)`, returns ordinary resources:

- a `Directory` for `/etc/apt/keyrings` (present on apt 2.4 and later, so on all four images; kept for safety);
- a `File` with the vendor's public key, at `/etc/apt/keyrings/<name>.asc`, mode 0644;
- a `File` with a deb822 source, at `/etc/apt/sources.list.d/<name>.sources`, with `Signed-By:` naming that key and `Architectures:` from `dpkg --print-architecture`.

`Suites:` is per source: Docker uses the host's codename, Caddy's repository uses the fixed suite `any-version`. No new `Resource` variant, so the journal format does not change.

**The keys are embedded in the binary,** with their fingerprints in the source, and are never downloaded at apply time. Fetching a key over HTTPS on the server trusts whatever that URL serves on that day; an embedded key is reviewed in a PR and covered by the release signature. The cost is that a vendor key rotation needs a vps-ready release. A weekly CI job checks the embedded keys against the vendors' published ones and opens an issue when they differ.

Rollback deletes the files. A `Package` installed from the source is not removed on rollback (it is labeled partial today, and stays so); the plan says so.

### `deploy.docker`

Installs Docker Engine from Docker's repository (`docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin`) and writes `/etc/docker/daemon.json` (with a `Directory` for `/etc/docker` first):

```json
{
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false,
  "ip": "127.0.0.1",
  "default-network-opts": { "bridge": { "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1" } }
}
```

- **Not applicable** when the distro's `docker.io`, `podman-docker` or distro `containerd`/`runc` are installed. It says which, and does not remove them: removing a running container stack is not a hardening step.
- **Docker already installed** (from Docker's repository or otherwise): the module only manages `daemon.json`. An existing `daemon.json` is merged key by key: keys we set are added or changed, other keys are kept, and the plan shows the diff. A file that is not valid JSON makes the module not applicable.
- **A new reload, `DockerRestart`:** `dockerd --validate --config-file /etc/docker/daemon.json`, then `systemctl try-restart docker.service`. The keys above are not reloadable on SIGHUP, so it is a restart. The restart stops running containers unless `live-restore` was already on. When containers are running and `live-restore` is off, the plan lists them and says they will restart, and that a rollback restarts them again. That note is the warning; `--yes` still means yes.
- The iptables firewall backend stays the default. Docker's nftables backend is still experimental in Docker 29. In iptables mode Docker sets `ip_forward=1` and a `FORWARD` policy of drop; `kernel.sysctl` does not touch either. The plan says that a host that routes other traffic (a WireGuard peer, a subnet router) needs its own forward rules.
- Unattended upgrades leave the Docker and Caddy origins out by default, and vps-ready does not change that. So `updates.auto` does not restart Docker on its own, and Caddy gets no automatic security updates either; the user docs say so.

**`FW-002` (published ports bypass the firewall).** `firewall.inbound` filters only the `input` hook; a published port is DNATed and forwarded, so the input chain never sees it. The fix in M5 is the loopback default above:

- It covers the default bridge (`ip`) and networks created after the restart (`default-network-opts`). Existing networks, such as a running compose project's, keep their binding until they are recreated (`docker compose down`, then `up`). The plan says so when such networks exist.
- With an IPv4 binding address, Docker does not publish on IPv6, so an upstream must be `127.0.0.1`, not `localhost` (which may resolve to `::1`). The user docs say so.
- A user who writes an address (`-p 0.0.0.0:8080:80`) gets what they asked for. `FW-002` keeps reporting every port published on a public address, with the hint that the default is now loopback.

Filtering the `forward` hook ourselves is left out (see Not in M5): it would have to stay correct across Docker's own rule changes, and Docker reworked its chains in 29.0.

**The firewall and a Docker installed by the same apply.** `firewall.inbound` accepts input from `docker0` and Docker's `br-*` bridges only when Docker is present at plan time. On a fresh host with `deploy.docker` in the same profile, it plans as if Docker were present (as `ssh.server` already looks at `user.admin` in the same profile). `iifname` rules for an interface that does not exist yet are valid nftables, so one apply is enough.

**The docker group.** Membership is root. `deploy.docker` adds nobody to it; `deploy.user` does only when asked (below).

### `deploy.proxy` (Caddy)

Installs Caddy from its repository and writes `/etc/caddy/Caddyfile` from the profile:

```toml
[modules."deploy.proxy"]
sites = [
  { domain = "app.example.com", upstream = "127.0.0.1:8080" },
]
```

- `sites` is required and must not be empty. One block per site: `reverse_proxy` to the upstream, with Caddy's automatic HTTPS. No other directives in M5.
- The Caddyfile starts with a vps-ready header line. A Caddyfile without that header (a hand-written one) is never overwritten: the module says so and only makes sure Caddy is installed.
- **Order:** a `Directory` for `/etc/caddy`, the Caddyfile, then the package. Caddy's package marks `/etc/caddy/Caddyfile` as a config file, and `Package` already installs with `--force-confold`, so dpkg keeps our file and Caddy's first start serves it instead of the default page. The layer 2 test checks this.
- **A new reload, `CaddyReload`:** `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`, then `systemctl try-reload-or-restart caddy.service`. A failed validate fails the module and the apply rolls back.
- **Preflight notes, not refusals:** a domain that does not resolve to one of the host's addresses, and port 80 or 443 not allowed by `firewall.inbound`. Certificates need both, but DNS may be changing while the user runs apply, so these are warnings. The DNS check is a resolver lookup at plan time (the only network use besides package installs) and is skipped with a note when the lookup fails.
- Nginx and Traefik stay out (decision D12).

### `deploy.user`

Creates a login user for CI deploys, separate from the admin:

```toml
[modules."deploy.user"]
name = "deploy"
keys = ["ssh-ed25519 AAAA... ci@example.com"]
command = "/usr/local/bin/deploy-app"   # optional
docker = false
```

- Every key is written with `restrict`. With `command`, also `command="<command>"`, so the key runs that one program, as the deploy user, and nothing else. `check_params` refuses a key that already has options (the same check as `user.admin`), so options are never doubled.
- With `command`, a sudoers drop-in `/etc/sudoers.d/90-vps-ready-deploy` allows `<name> ALL=(root) NOPASSWD: <command> ""`: that command, as root, with no arguments. The forced command runs as the deploy user, so a script that needs root re-runs itself with `sudo`; the docs show how. The drop-in is checked with `visudo -cf` before it is installed. Without `command`, no sudo at all.
- **Refused at plan time:** a `command` that is not an absolute path to a root-owned file that is not group- or other-writable (the same check as the safety timer's binary); a `name` equal to `user.admin`'s; an existing login account that vps-ready did not create, so an existing user never gets restricted keys or the docker group by surprise.
- `docker = true` adds the user to the `docker` group. The plan says in words that this is root access.
- The account has a locked password. It reuses `user.admin`'s `User` and `AuthorizedKeys` resources, with the `#81` checks on the key file.
- No safety timer: the admin's login is untouched.

### Profiles and the wizard

- The `web` profile gains `deploy.docker`. `deploy.proxy` and `deploy.user` need values only the user has (domains, keys), so they are not in a built-in profile.
- The wizard, when the profile includes `deploy.docker`, asks for domains and upstreams (none is fine). With at least one, it adds `deploy.proxy`, and the profile is saved to `vps-ready.toml` as in M4.

### Packages: `.deb` only

The release builds `vps-ready_<ver>_amd64.deb` and `_arm64.deb` with nFPM from the existing musl binaries. vps-ready runs only on Debian and Ubuntu, so `.rpm` and `.apk` would be packages for systems it refuses to run on.

- The binary goes to `/usr/bin/vps-ready`, with the `vpsready` link. No maintainer scripts; installing the package changes nothing on the system.
- The `.deb` is a release asset, listed in `checksums.txt`, covered by the cosign signature and the provenance attestation. There is no apt repository and no embedded deb signature (apt does not check those; it checks repository signatures). Install with `apt install ./vps-ready_0.5.0_amd64.deb` after the usual checksum step.
- nFPM is installed in CI from a pinned release binary, checked against that release's `checksums.txt`.
- **Moving from `install.sh` to the package.** `/usr/local/bin` comes first on `PATH`, so an old `install.sh` binary would shadow the package. The install page says to remove `/usr/local/bin/vps-ready` and `vpsready` first, and `vps-ready version` warns when another `vps-ready` is on `PATH`.
- **Fix `#75` first.** The safety timer's boot hook names the binary's path, so switching between the two paths while a transaction is pending would break the hook. When the switch is armed, `apply` now copies the running binary (after the usual checks) to `/var/lib/vps-ready/bin/vps-ready` and points the timer and the hook at that copy, so moving or upgrading the installed binary cannot break an unattended rollback, and nothing looks in several places. A transaction armed by v0.4.0 keeps its old hook.

### SBOM

`cargo cyclonedx --manifest-path crates/vps-ready/Cargo.toml --format json --spec-version 1.5 --target all` gives one SBOM for the binary's crate, renamed to `vps-ready-<ver>.cdx.json`, attached to the release and listed in `checksums.txt`. It is attested with `actions/attest` (pinned by SHA), with the tarballs and `.deb` files as subjects and the SBOM as the predicate (`https://cyclonedx.org/bom`). `cargo-cyclonedx` is installed in CI with `cargo install --locked` at a pinned version.

### Changes to earlier docs

This plan departs from earlier docs; PR 8 updates them:

- `release.md`: `.rpm`/`.apk`, GPG-signed packages and an apt repository at v0.5 become "`.deb` release assets; the rest when needed".
- `architecture.md`: `--deadman=off|selftest` and `export cloud-init` move from M5 to v0.6.0; the two new reloads.
- `security-baseline.md`: `deploy.user`'s command is the user's choice, not fixed to `/usr/local/bin/deploy-app`; Nginx+certbot and rootless Docker/Podman are not offered in M5.
- `m3-plan.md`: its pointers to M5 for Tailscale and `--deadman=off` now mean v0.6.0.
- `decisions.md`: a new decision for the split.

### Not in M5

| Planned before | M5 | When |
|---|---|---|
| `net.tailscale`, close public 22 | | v0.6.0, with a confirm that must arrive over `tailscale0` |
| `--deadman=off\|selftest` | | v0.6.0, with the export |
| `export cloud-init` | | v0.6.0; a small `#cloud-config` that pins version and SHA256 (AWS limits user data to 16 KB) |
| `.rpm`, `.apk` | `.deb` only | If vps-ready supports those distros |
| apt repository | Release assets | When asked for |
| Filtering Docker's `forward` hook | Loopback by default, `FW-002` reports the rest | If loopback proves not enough |
| Rootless Docker, Podman | Docker Engine | If asked for |
| Nginx, Traefik | Caddy | Decision D12 |
| `/etc/vps-ready/config.toml` | | M6, with `drift` |

## Testing

**Layer 1:**
- `apt_source`: the files for each of the four codenames and both architectures, Caddy's fixed suite; rollback removes them; an embedded key whose fingerprint does not match fails a unit test.
- `deploy.docker`: fresh host; Docker already installed with no `daemon.json`; an existing `daemon.json` with other keys (merged); invalid JSON (not applicable); `docker.io` installed (not applicable); running containers with `live-restore` off (the restart note); existing user-defined networks (the recreate note).
- `firewall.inbound` with `deploy.docker` in the same profile on a host without Docker: the bridge rules are planned.
- `FW-002` with the new hint, from the fixtures already in the repo.
- `deploy.proxy`: the Caddyfile for one and several sites; empty `sites`, a bad domain or upstream refused by `check_params`; a hand-written Caddyfile left alone; the DNS and firewall notes, and a failed lookup.
- `deploy.user`: with and without `command`; `docker = true`; a writable `command`, the admin's name, an existing account and a key with options, each refused; the sudoers line.
- The `web` profile and wizard snapshots, updated, plus a wizard run that adds a domain.

**Layer 2 (containers):** the vendor sources plus `Package` against Docker's and Caddy's real repositories on all four images (network allowed in this job): Caddy keeps our Caddyfile, `docker run` works without recommended packages, and rollback leaves no source or key behind. `visudo -cf` on the sudoers drop-in.

**Layer 3 (VMs):** cycle 8 on all four images, with a test profile that uses Caddy's internal CA (`tls internal`) instead of a real certificate:
- `apply` with `web`, one site pointing at a container, and `deploy.user`;
- `curl -k --resolve app.example.com:443:127.0.0.1 https://app.example.com` answers through Caddy;
- a container published without an address is not reachable on the VM's own address;
- the deploy key runs only its command;
- `rollback --last`, then Docker's and Caddy's config files and sources are gone.

**Release:** the release workflow on a test tag in a fork builds the `.deb` and the SBOM; `dpkg -i` in a container, then `vps-ready --version`.

## PR sequence

1. **`docs: plan M5`** (this document).
2. **`feat(resource): vendor apt sources`**: the helper, embedded Docker and Caddy keys with fingerprints, the weekly key check. *Parallel with 5 and 6.*
3. **`feat(modules): deploy.docker`** (needs 2): the module, `DockerRestart`, the `daemon.json` merge, the `FW-002` hint, `firewall.inbound` planning for a Docker in the same profile, the `web` profile.
4. **`feat(modules): deploy.proxy`** (needs 2 and 3): the module, `CaddyReload`, the wizard's domain question.
5. **`feat(modules): deploy.user`**: the module and the sudoers drop-in.
6. **`fix(deadman): run the timer and boot hook from a private copy of the binary`** (`#75`), then **`ci(release): .deb and SBOM`**, with the `PATH` warning in `version`.
7. **`test(vm): deploy cycle`** (needs 3 to 5): cycle 8.
8. **`docs(site): deployment modules`** (needs 3 to 6): guides, `modules` reference, the install page with the `.deb`, and the doc changes listed above.
9. **`chore: release v0.5.0`**.

Waves: {2, 5, 6} → 3 → 4 → {7, 8} → 9.

## Decided by the owner (2026-10-31)

All five recommendations were accepted:

1. **Split M5 into v0.5.0 (deploy modules, `.deb`, SBOM) and v0.6.0 (Tailscale, close 22, `--deadman=off`, cloud-init export).** Recommended: v0.5.0 then cannot lock out an admin. Alternative: one v0.5.0 with everything.
2. **Embed vendor apt keys in the binary**, with a weekly CI check. Recommended over downloading the key at apply time.
3. **`.deb` only**, no `.rpm`/`.apk` and no apt repository. Recommended: vps-ready does not run on rpm or apk systems.
4. **Docker publishes on loopback by default** (`ip` and `default-network-opts`), with `FW-002` reporting the rest, instead of filtering the `forward` hook. Recommended for staying out of Docker's own chains.
5. **The `web` profile gains `deploy.docker` only**; Caddy joins when the user gives a domain (in the wizard or a profile). Recommended: a hardening run should not start a web server nobody configured. Alternative: new modules are opt-in only in v0.5.0.
