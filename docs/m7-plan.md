# M7 plan: web through a tunnel, depth, and v1.0

> **Status: accepted (2026-11-20); wave 1 shipped in v0.7.0.** `net.tunnel`, `deploy.proxy` `behind_tunnel`, the tunnel in the `private` profile and the wizard, and the journal `format` field are built; the rest is not. Every recommendation in [Decisions](#decisions) was accepted as written.

M7 lets a web app run with no public port through a Cloudflare Tunnel, adds drift detection, CI-friendly audit output and security-key SSH logins, and then makes the tool stable as v1.0.

It has three parts, in this order:

1. **`net.tunnel`**: Cloudflare Tunnel, with `deploy.proxy` behind it on loopback. With it, a host running a web app can close 80 and 443 too, so the `private` profile reaches zero public TCP ports even with a website.
2. **Depth**: `drift` with `/etc/vps-ready/config.toml`, SARIF and JUnit output for `audit`, a JSON Schema for profiles, and security-key (FIDO2) SSH logins.
3. **v1.0**: what "stable" means for the profile format, the CLI, exit codes and the journal, and what must be true before tagging 1.0.0.

New distro families (Rocky and Alma, Fedora, Alpine) are not in M7. Earlier docs place them in M7; they now come on demand (see [Not in M7](#not-in-m7)). Ubuntu 26.04, a new release of a family already supported, is in.

**Assumes M6 is complete.** M6 shipped in v0.6.0, including `net.wireguard`, the `private` profile and the M6 wizard changes, which M7's wave 1 builds on.

Only one piece changes the SSH path: security keys. It gets the same lockout care as `ssh_via`. The tunnel never carries SSH routes that vps-ready sets up, but whoever controls the Cloudflare account can add one (see [Trust model](#trust-model)).

## Decisions

### Scope and releases

| Release | Piece | Changes | Safety timer |
|---|---|---|---|
| v0.7.0 | `net.tunnel` | Cloudflare's apt source and key, `cloudflared`, an unattended-upgrades origin, `vps-ready-cloudflared.service` (the connector, with a token from a root-only file) and a path unit that restarts it after an upgrade | no |
| v0.7.0 | `deploy.proxy` `behind_tunnel` | Caddy serves plain HTTP on loopback only; no certificates, no public 80 or 443 | no |
| v0.7.0 | `private` profile and wizard | a tunnel instead of 80 and 443 | as in M6 |
| v0.7.0 | Journal `format` field | `begin` records `format: 1` | |
| v0.8.0 | `/etc/vps-ready/config.toml` | every apply records the profile it applied | as the apply |
| v0.8.0 | `drift` | nothing; reports what changed since the last apply | |
| v0.8.0 | `audit --format sarif\|junit` | nothing; new output formats | |
| v0.8.0 | JSON Schema | nothing on the host; `vps-ready schema` and a release asset | |
| v0.8.0 | Ubuntu 26.04 | data tables, the test matrix, the M3 and M6 session assumptions re-checked under sudo-rs | |
| v0.9.0 | `ssh.server` `security_keys` | the sshd drop-in accepts only security-key logins (with an exemption for `deploy.user`) | yes |
| v1.0.0 | Stability | `docs/stability.md`, `sshd-config` fuzz targets, a review of every name before it freezes | |

The split follows the owner's suggestion, with three changes:
- The JSON Schema moves into v0.8.0 with `config.toml`. Both describe the same format, and the schema should ship in a release before 1.0 freezes it.
- The journal `format` field moves to v0.7.0. Every journal written from then on carries it, so the 1.x promise ("reads every journal since 0.7.0") has a field to check from the start.
- auditd is not in v0.9.0 (decision 16). After 1.0, a new opt-in module is an additive change, so it does not need to land before the freeze.

SARIF and JUnit depend on nothing else, so they can move into v0.7.0 if the tunnel slips.

The registry order becomes `user.admin`, `ssh.server`, `net.tailscale`, `net.wireguard`, `net.tunnel`, `deploy.docker`, `firewall.inbound`, `ssh.bruteforce`, `kernel.sysctl`, `updates.auto`, `deploy.proxy`, `deploy.user`. `net.tunnel` comes before `deploy.proxy`, which reads whether a tunnel is planned.

### Web through a tunnel: `net.tunnel`

```toml
[modules."net.tunnel"]
provider = "cloudflare"                 # the only value in M7
token_file = "/root/cloudflared-token"  # optional
auto_update = true                      # default
```

**What it is.** `cloudflared` on the host opens outbound connections to Cloudflare's edge, and the edge sends requests for the user's hostnames back through them. No inbound port is needed. Cloudflare's firewall page asks only for outbound port 7844 (TCP for `http2`, UDP for `quic`), and our `established,related` rule covers the replies. `firewall.inbound` filters inbound traffic only, so nothing changes there.

**Remotely-managed tunnels only.** Cloudflare has two kinds:
- **Remotely managed:** created in the dashboard (or the API). Its routes (public hostname to local service) live at Cloudflare, and the connector needs only the tunnel's token.
- **Locally managed:** created with `cloudflared tunnel create`, which needs `cert.pem` from `cloudflared tunnel login`. That certificate can create and delete tunnels and DNS records for the whole account, which is far more than a single host needs.

vps-ready supports the first kind only. It runs the connector. The user creates the tunnel and its routes in the dashboard, and the plan says what to enter there (below). vps-ready cannot see those routes.

**Install.** Cloudflare's repository through the M5 `apt_source` helper: `https://pkg.cloudflare.com/cloudflared`, suite `any`, component `main`, for every Debian and Ubuntu release. The repository also has per-codename suites, but Cloudflare's own instructions use `any`, and its `Release` file lists amd64 and arm64. The binary key (`cloudflare-main.gpg`, RSA 4096, created 2025-10-23) is embedded with its fingerprint, and the weekly key check gains it. Then `Package cloudflared`.

**Updates.** With `auto_update = true`, `/etc/apt/apt.conf.d/52vps-ready-cloudflared` adds `Unattended-Upgrade::Origins-Pattern { "origin=cloudflared,codename=any"; };`. The repository's `Release` file says `Origin: cloudflared` and `Codename: any`, so `${distro_codename}` would never match. cloudflared's own updater does nothing for package-manager installs (Cloudflare's run parameters page), and the unit passes `--no-autoupdate` anyway.

**Restart after an upgrade.** The package's `postinst` only creates a symlink and a marker file (cloudflared's `postinst.sh`); it restarts nothing. Without a restart, an unattended upgrade leaves the old binary running until the next reboot. vps-ready adds a path unit, `vps-ready-cloudflared-restart.path` with `PathChanged=/usr/bin/cloudflared`, which starts `vps-ready-cloudflared-restart.service`.

A path unit rather than an apt `DPkg::Post-Invoke` hook: it fires for any way the binary is replaced (unattended-upgrades, `apt`, `dpkg -i`), runs only when the binary changes rather than after every dpkg run on the host, and is `File`s and a `Service` that rollback removes like the rest. It is installed only together with the connector unit, so a host without a token does not get a failing unit at every upgrade.

**The restart must converge, not just fire once.** dpkg hard-links the old binary to `cloudflared.dpkg-tmp` before it renames the new one into place, and the link count change (an attribute change) can trigger the path unit before the rename. systemd also stops watching while the triggered service runs and does not look again afterwards. So a plain `try-restart` can start the old binary again and then miss the rename. The restart service is a short `sh` script in the unit, rendered from a template and checked with `sh -n`:
1. Wait, for at most 60 seconds, until neither `/usr/bin/cloudflared.dpkg-new` nor `/usr/bin/cloudflared.dpkg-tmp` exists.
2. `systemctl try-restart vps-ready-cloudflared.service`. Under `Type=notify` this returns once the new process is connected, or fails at `TimeoutStartSec`.
3. Compare the inode of `/proc/<MainPID>/exe` with that of `/usr/bin/cloudflared`. If they match, or the unit is not running, stop. Otherwise go back to step 1, at most five times, 5 seconds apart.
4. If they still differ, exit non-zero with "cloudflared runs an old binary", which shows in `systemctl --failed` and in `drift` (through `net.tunnel`'s verify, which makes the same comparison).

**The connector unit.** Since 2025.4.0, `cloudflared service install <token>` writes the token to a file under `/etc/cloudflared` and passes `--token-file`, so the token is no longer in `ExecStart` (cloudflared's `linux_service.go` at 2026.11.1). vps-ready still writes its own unit, for what that one lacks: it runs cloudflared as root, unsandboxed, and its `cloudflared.service` is the name Cloudflare's dashboard instructions create, so the two would collide.

```ini
# /etc/systemd/system/vps-ready-cloudflared.service
# Written by vps-ready (net.tunnel). `vps-ready rollback --last` restores
# the previous state; edits here are replaced by the next apply.
[Unit]
Description=Cloudflare Tunnel connector (vps-ready net.tunnel)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
TimeoutStartSec=30
LoadCredential=token:/root/cloudflared-token
ExecStart=/usr/bin/cloudflared tunnel --config /etc/vps-ready/cloudflared.yml --metrics 127.0.0.1:20241 run --token-file ${CREDENTIALS_DIRECTORY}/token
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
IPAddressDeny=link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 168.63.129.16 fc00::/7
IPAddressAllow=localhost <each nameserver in /etc/resolv.conf at apply time>
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

- `--token-file` needs cloudflared 2025.4.0 or later; the repository has 2026.11.1 today. The plan refuses an installed `cloudflared` older than that (only possible with a pinned or hand-installed binary).
- `LoadCredential=` (systemd 247; Debian 12 has 252, Ubuntu 22.04 has 249) copies the root-only file into a directory only the service's user can read, and `DynamicUser=yes` makes that user a fresh unprivileged one. cloudflared never runs as root.
- The token is never in argv, the unit file, the journal, the plan or the profile. The profile holds only the path, and vps-ready never opens the file. The file must be a regular file owned by root with no group or other permissions, and not a symlink, as for `net.tailscale`'s `auth_key_file`.
- **A rotated token** takes effect at the next start, since `LoadCredential=` copies the file then. The docs say to run `systemctl restart vps-ready-cloudflared` after replacing it.
- **Its own config file.** Without `--config`, cloudflared searches `/etc/cloudflared` and `/usr/local/etc/cloudflared` for a config file (cloudflared's `config/configuration.go`), so a stray `config.yml` from an earlier setup would change what the connector does. The unit names `/etc/vps-ready/cloudflared.yml` instead, a `File` (0644, no secrets) holding the header comment and `no-autoupdate: true`. It is not empty on purpose: an empty config (`--config /dev/null`) makes cloudflared log an error-level line at every start, which would look like a fault in `journalctl`.
- **Starting is the gate.** Under `Type=notify`, cloudflared sends `READY=1` only after its first connection to the edge is registered (`notifySystemd` in cloudflared's `tunnel/cmd.go`). So the `Service` resource's start fails when the token is bad or port 7844 is blocked, and the apply rolls back. `TimeoutStartSec=30` is set explicitly: Cloudflare's unit uses 15, and 30 leaves room for the QUIC to HTTP/2 fallback on networks that drop UDP.
- `--edge-ip-version` defaults to `4`. On a host with no IPv4 default route, the unit gets `--edge-ip-version auto`, with a note.
- **The metrics port.** `127.0.0.1:20241`, fixed so verify can find it. The plan refuses when something else already listens there. Any local user can read the metrics (connection counts, the tunnel's ID, the cloudflared version) but not the token. The plan says so.
- The sandboxing lines are checked against a running connector in layer 2 (QUIC, ICMP proxy warnings), and dropped one by one if they break it.
- **No token file:** the module installs `cloudflared`, the update origin and the path unit, plans no connector unit, and says "create a tunnel in the Cloudflare dashboard, save its token to a root-only file, set `token_file` and apply again". This mirrors `net.tailscale` without a key.
- **Not applicable** when a `cloudflared.service` (Cloudflare's own install) or another cloudflared unit exists. That is a hand-made setup, and `deploy.proxy`'s `behind_tunnel` works with it.

**Verify** reads back what the start already proved: `cloudflared tunnel --metrics 127.0.0.1:20241 ready` exits 0 while the connector has at least one registered connection (the `/ready` endpoint returns 200, 503 otherwise). It also checks that the running process's binary is `/usr/bin/cloudflared` (the inode comparison above), and whether the address filter is in effect (see [Trust model](#trust-model)).

**Blast radius of a failure.** A failed start or verify rolls back the whole transaction, as any failure does. In the wizard's first apply, that includes the SSH and firewall hardening. Keeping the transaction whole is the engine's rule, and splitting it would leave a half-applied profile. So the error names the tunnel as the cause ("the tunnel did not connect: check the token in /etc/vps-ready/cloudflared-token and that outbound port 7844 is open, then apply again"), and the wizard checks the token file's format before planning.

**What the plan prints**, so the dashboard side is right:

```
note: in the Cloudflare dashboard, give this tunnel a published route for each site:
        app.example.com  ->  http://127.0.0.1:80
      With deploy.proxy, Caddy answers on 127.0.0.1:80. Without it, point the
      route at your app's loopback address instead. Only loopback targets work:
      the connector cannot reach Docker bridges or private networks, so such a
      route answers 502.
note: anyone who controls this Cloudflare account can route the internet to any
      address this host reaches on loopback, including SSH. Turn on two-factor
      login for the account, and add no routes to ssh:// or other local services.
```

**Rollback** stops, disables and removes the connector unit, the path unit and its service, `/etc/vps-ready/cloudflared.yml`, the apt source, the key and the origin file. The package stays, as for every `Package`, and the token file stays (it is the user's). The tunnel then shows as down in the dashboard; deleting it there is the by-hand step.

**Export.** `export cloud-init` refuses `token_file`, for the reason it refuses Tailscale's `auth_key_file`: user-data is readable through the metadata service. `net.tunnel` without `token_file` is exported, and the first login sets the token and applies again.

**Tailscale Funnel** stays out of M7 (only `ts.net` names, three ports). `provider` exists from the start so that a second value later is additive.

### Trust model

A remotely-managed tunnel's routes are set at Cloudflare. Whoever controls the account (or a stolen API token with tunnel rights) can add a route from a public hostname to any address the connector can reach: `ssh://127.0.0.1:22`, a database on loopback, the cloud metadata service at `169.254.169.254`, or the provider's private network. Such a route goes around `ssh_via` and the inbound firewall, while `SSH-009` and `FW-003` still pass, since both look at inbound traffic.

What M7 does about it:
- **The unit limits where the connector can connect.** `IPAddressDeny=` drops link-local (the metadata service at `169.254.169.254`), multicast, the private ranges (RFC 1918, `100.64.0.0/10`, `fc00::/7`) and Azure's platform address `168.63.129.16`. `IPAddressAllow=` keeps loopback and the resolvers in `/etc/resolv.conf`, which on some clouds are themselves link-local or private. On Google Cloud the resolver is the metadata address and on Azure it is `168.63.129.16`, so those stay reachable there, and the plan says so. Loopback cannot be limited by port this way, so loopback SSH and loopback databases stay reachable through a route.
- **The resolvers are read at apply time.** IPv6 link-local entries lose their zone ID (`fe80::1%eth0` becomes `fe80::1`), which `IPAddressAllow=` does not accept. A Tailscale node logged in by hand with `--accept-dns` lists `100.100.100.100`, which is then allowed like any resolver (`net.tailscale` itself joins with `--accept-dns=false`). When the resolvers change later (a new DHCP lease, a network change), the connector may fail to resolve the edge until the next apply; `drift` shows it as the connector unit's `IPAddressAllow=` line differing, with "the resolvers in /etc/resolv.conf changed since the last apply: apply again".
- **The filter can be silently off.** systemd enforces `IPAddressDeny=` with cgroup BPF programs. Without them (inside LXC or OpenVZ, or a kernel without cgroup BPF), systemd only logs a warning and runs the unit unfiltered. The plan notes it when the host is a container (`systemd-detect-virt --container`) or has no unified cgroup hierarchy, and verify looks for systemd's "does not support BPF/cgroup firewalling" message for this unit since its start and turns it into a note: "the connector's address filter is not in effect on this host".
- **The plan's note** (above), and the docs, say to turn on two-factor login for the account and to add no routes other than the web ones.
- **`SSH-009` gains a caveat:** when a cloudflared connector runs, its finding says "a Cloudflare Tunnel connector runs on this host; its account can route to SSH on loopback". The control still passes, since the inbound path is closed.
- Limiting the connector's loopback ports through the firewall (an output rule matched on the unit's cgroup) is listed under Not in M7.

### `deploy.proxy` behind the tunnel

```toml
[modules."deploy.proxy"]
behind_tunnel = true
sites = [{ domain = "app.example.com", upstream = "127.0.0.1:8080" }]
```

The rendered Caddyfile:

```
# Written by vps-ready (deploy.proxy). ...
{
	default_bind 127.0.0.1 [::1]
	servers {
		trusted_proxies static 127.0.0.1/32 ::1/128
		client_ip_headers Cf-Connecting-Ip
	}
}

http://app.example.com {
	@plain header X-Forwarded-Proto http
	redir @plain https://{host}{uri} 308
	reverse_proxy 127.0.0.1:8080 {
		header_up X-Forwarded-For {client_ip}
		header_up X-Forwarded-Host {host}
	}
}
```

- **TLS ends at Cloudflare's edge.** The `http://` site address turns off Caddy's automatic HTTPS for that site (Caddy's Automatic HTTPS docs), so Caddy needs neither port 80 for the ACME challenge nor 443, and gets no certificate. The hop from cloudflared to Caddy is loopback.
- **HTTPS redirect.** A visitor on `http://` reaches Caddy with `X-Forwarded-Proto: http` set by the edge, and Caddy redirects. Without the header, nothing is redirected, which is safe. The docs also point to the dashboard's "Always Use HTTPS", which redirects at the edge.
- **Loopback only.** `default_bind` (`127.0.0.1`, plus `[::1]` only when loopback has it, since Caddy cannot bind `::1` where IPv6 is disabled) keeps Caddy off public addresses, so even with `firewall.inbound` not applied, nothing listens publicly. `FW-003` then shows no web port.
- **Host header.** Caddy matches the site by `Host`. cloudflared's `httpHostHeader` is empty by default, which is expected to pass the visitor's hostname through. The release gate checks it end to end. If it does not hold, the plan's route note adds "HTTP Host Header: app.example.com".
- **Client addresses.** Every request reaches Caddy from `127.0.0.1`. With loopback as the only trusted proxy, Caddy takes the visitor's address from `Cf-Connecting-Ip`, which the edge sets. `X-Forwarded-For` is not trusted as a source: its leftmost value comes from the visitor. For the upstream, `header_up X-Forwarded-For {client_ip}` replaces the header with that one address; Caddy would otherwise append to the incoming one for a trusted peer. For the same reason `header_up X-Forwarded-Host {host}` replaces a visitor-supplied `X-Forwarded-Host`, which a trusted peer would keep. Layer 2 sends a forged `X-Forwarded-For` and `X-Forwarded-Host` and checks the upstream sees only the `Cf-Connecting-Ip` address and the real host; the release gate checks a real visit.
- **Plan-time changes:** the DNS note ("app.example.com does not point here") is skipped, since the domain points at Cloudflare. The `firewall.inbound` note about opening 80 and 443 is replaced, when `allow` still opens them, by "80/tcp and 443/tcp are open but Caddy listens on loopback only: drop them from `allow`". A note when no tunnel connector is planned or running ("nothing forwards to Caddy yet: add `net.tunnel`").
- **Switching** `behind_tunnel` on or off rewrites the Caddyfile and reloads Caddy in one apply. Turning it off brings back automatic HTTPS, which needs 80 and 443 open, and the existing note says so.
- One mode per host: every site is behind the tunnel, or none is (see Not in M7).

### Zero public ports, completed

| Setup | Public on the host |
|---|---|
| Tailscale for SSH, tunnel for the web | No inbound port |
| WireGuard for SSH, tunnel for the web | UDP 51820 only, which answers nothing without a valid handshake |
| A VPN for SSH, no tunnel, a web app | 80 and 443 (as in M6) |

**The `private` profile and the wizard.** When the profile is `private` and the user adds a domain, the wizard's ports question gains one choice:

```
? How do visitors reach this site
  > Through a Cloudflare Tunnel (no public ports; DNS on Cloudflare)
    Directly, on ports 80 and 443 (Caddy gets the certificate)
```

The tunnel choice adds `net.tunnel` and `behind_tunnel = true`, and leaves `allow` empty. The token is asked hidden. The wizard writes it itself, before the plan and outside the transaction, to `/etc/vps-ready/cloudflared-token`, opened with `O_CREAT | O_EXCL` and mode 0600, and sets that path as `token_file`. It is never a `File` resource, so its bytes never reach the journal's `files/<n>` copies. Unlike Tailscale's one-off key it is needed at every start, so it stays. If the file already exists, the wizard asks whether to keep it. Outside the `private` profile the question is not asked; a profile file can still combine the modules.

### Drift and `/etc/vps-ready/config.toml`

**`config.toml` records what was applied.** Every apply that changes something writes `/etc/vps-ready/config.toml` (0600, root) as a `File` resource in the same transaction, so a rollback (including the dead-man's) restores the previous one.
- **Resolved, not as written:** `schema = 1`, no `extends`, and each applied module's full params after the merge with its base profile, with defaults written out as values. If a later release changes the built-in `web` profile or a default, drift does not report a change nobody applied.
- **What was applied, not what was asked:** the `private` profile's staged `ssh_via = "vpn"` is recorded as the interface it resolved to (`ssh_via = "tailscale0"`) after step 2, and as absent after step 1, when SSH stayed public.
- **Merged per module:** `apply --module kernel.sysctl` replaces only that module's table. A module dropped with `enabled = false` stays in the file (vps-ready does not undo it), with its last params.
- **A missing or partial record counts as a change.** When `config.toml` is missing, or lacks a table for a selected module, the plan includes writing it, even on a host that is otherwise converged. So "run `apply` once" always records the modules it selects, and never ends with "nothing to do" while drift still cannot compare.
- It holds no secrets: Tailscale and the tunnel are given as paths, and authorized keys are public.
- `export cloud-init` keeps writing `/etc/vps-ready/profile.toml`; the first apply then writes `config.toml` like any other.

**`vps-ready drift`** runs a read-only plan against `config.toml`, then each module's `verify`, which is also read-only:

```
$ sudo vps-ready drift
ssh.server  /etc/ssh/sshd_config.d/00-vps-ready.conf  changed since txn 20261203T101500Z
            -PasswordAuthentication no
            +PasswordAuthentication yes
kernel.sysctl  net.ipv4.conf.all.rp_filter  runtime 0, file 2
net.tunnel  verify: vps-ready-cloudflared.service is not active
3 drifted. To restore: sudo vps-ready apply --profile /etc/vps-ready/config.toml
```

- **Session refusals become notes, and the comparison goes on.** Many plan-time refusals are about the applying session (no SSH session, not through `ssh_via`, not logged in with a security key, `security_keys` refusal 4), and drift often runs from cron. In drift they are reported as notes, do not count as drift, and do not stop the module's comparison: `ssh.server` is still compared when its refusal 4 fires.
- **Other refusals are drift.** A refusal about the host's state, not the session, means it no longer matches what was applied (the admin's `sk-` key removed, the `ssh_via` interface gone, an old `cloudflared`). Drift reports it with the module, and it counts.
- **Drift complements audit.** `audit` asks "is this host secure"; `drift` asks "is this host still what was applied". A drifted file that still passes every control shows only in `drift`; a failed control that no module manages shows only in `audit`.
- Exit codes: 0 no drift, 1 drift, 2 error (as `audit`). `--json` lists each drifted resource with its module.
- **No `state.json`.** The plan already compares every resource with the host (file content, sysctl runtime values, service state, `wg0`'s runtime peers), so a hash store would repeat it and could itself go stale. The journal adds the one thing the plan lacks: when the file was last written, and by which transaction, from the newest `files/<n>.after` for that path.
- A module that is now not applicable (Docker removed) is reported as such, not as a change.
- **No `config.toml`:**
  - with no transactions in the journal: "nothing has been applied on this host yet", exit 0;
  - with transactions (applied before 0.8.0): "this host was set up before vps-ready 0.8.0 recorded what it applied; run `apply` once with your profile", exit 2. It never reports "no drift" for a host it cannot compare.
- **Partly recorded:** a module that appears in a journal transaction but has no table in `config.toml` (a pre-0.8 host whose first later apply used `--module`) is listed as "not recorded", and drift exits 2 even when everything recorded matches. The list says which modules an apply still has to record.
- No `drift --fix`; the printed `apply` is the fix, behind the same plan, prompt and timer. No drift timer or notifications in M7.

### JSON Schema for profiles

`vps-ready schema` prints a JSON Schema (draft 2020-12) for the profile format, generated with `schemars` from the same `deny_unknown_fields` structs, so it cannot drift from the parser. Each release attaches it as `vps-ready-profile.schema.json`, and the site serves it at a stable URL. A profile can name it on its first line (`#:schema <url>`) for editors that read that comment.

`schemars` is the one new dependency in M7, already listed as "later" in the architecture doc. Params parsed by hand into a newtype (`Domain`, `Upstream`, WireGuard keys) get a `pattern` or a description, not their full rules; the parser stays the authority. A test walks the registry and fails when a registered module has no entry in the schema, so a new module cannot be left out.

### `audit` output: SARIF and JUnit

`audit --format text|json|sarif|junit`. `--json` stays as a short form of `--format json`. The exit code does not change with the format.

**SARIF 2.1.0**, the only version GitHub code scanning accepts:
- `tool.driver.rules`: every control in the catalog, with `id` (the control ID), `shortDescription` (title), `fullDescription` (why), `help` (the fix command), and `properties.security-severity`: high 8.0, medium 5.5, low 3.0, which fall in GitHub's high, medium and low bands.
- `results`: fail as `kind: fail` (level from severity), unknown as `kind: open`. GitHub ignores `kind`, so an unknown shows as an alert at `note` level, and the docs say so. Pass and skip are not included, even with `--all`. Code scanning closes an alert when a later run under the same `automationDetails.id` no longer reports it, so a fixed control closes its alert; listing passes would add nothing there, and how other consumers display them varies.
- **Locations.** Code scanning shows a result only with at least one location, and these findings are about a host, not a source file. Each result gets a `logicalLocation` (the host name) and a `physicalLocation` whose URI is `<host>/<control ID>` under a `HOST` base, with `region.startLine = 1`. Code scanning then lists them, linking to a file that does not exist, and the docs say so.
- **One run per host:** `runs[].automationDetails.id` is `vps-ready/audit/<host>/`, so uploads from several hosts to one repository do not close each other's alerts.
- **Fingerprints:** `partialFingerprints.primaryLocationLineHash`, the only key code scanning uses, set from the host name and control ID, so a re-run updates an alert instead of adding one.
- The PR checks the output against the SARIF 2.1.0 JSON Schema in a test, and with one upload to a scratch repository by hand.

**JUnit XML**, for CI systems that render test reports:
- `<testsuites name="vps-ready audit">`, one `<testsuite>` per area (SSH server, Firewall, ...), one `<testcase>` per control with `classname` the area and `name` "SSH-002 Password login is off".
- Fail is `<failure>` with the finding, unknown is `<error>` (the check could not run), skip is `<skipped>`, and pass is an empty test case. JUnit consumers expect the whole suite, so every control is always listed, with or without `--all`.
- No schema check (JUnit has no formal one); a snapshot and a parse in the test.

### Ubuntu 26.04

Same family and adapters: the OS table, the codename for vendor sources (Docker, Caddy, Tailscale; cloudflared uses `any`), the VM image and the container image. Each vendor repository must publish the codename before its module claims 26.04; until then the module is not applicable there, with a note.

**sudo-rs.** Ubuntu 26.04 makes sudo-rs its default `sudo` (the original stays installable as `sudo.ws`). Several M3 and M6 assumptions involve sudo, so this PR re-checks them on 26.04 before anything else claims support:
- `confirm` finding the new SSH session through `sudo`'s process tree (the `sshd-session` ancestor, `SUDO_USER`);
- `user.admin`'s sudoers drop-in: that sudo-rs reads `/etc/sudoers.d/90-vps-ready-admin` with the same `@includedir` naming rules, honors the `nopasswd` and `password` forms, and that `visudo -cf` exists and validates it;
- `--deadman=off`'s logged-in-user checks, and the wizard's root check under `sudo`;
- OpenSSH (10.2, with `sshd-session`) and systemd versions, for the facts and the fact check.

A difference becomes a per-release data row or a fix in that PR. This PR lands before the security-key PR, which depends on the same session facts.

### Security-key SSH logins (FIDO2)

OpenSSH has supported security keys since 8.2, with the key types `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`, and `verify-required` (a PIN on the key) since 8.4. Every supported release ships newer: Debian 12 has 9.2, Debian 13 has 10.0, Ubuntu 22.04 has 8.9, Ubuntu 24.04 has 9.6 and Ubuntu 26.04 has 10.2. The server needs no hardware and no `libfido2`; only the client talks to the key. `user.admin` already accepts `sk-` key lines.

```toml
[modules."ssh.server"]
security_keys = "required"   # "allowed" (default: no change) or "required"
pin = false                  # true adds verify-required
single_security_key = false  # true accepts an admin with only one sk- key
```

**What changes in the drop-in:** `PubkeyAcceptedAlgorithms` lists only the two `sk-` types (and their `-cert-v01@openssh.com` forms); with `pin = true`, `PubkeyAuthOptions verify-required`. sshd already requires a touch by default. Passwords are already off (`SSH-002`), so a security key becomes the only way in for every user but the exemption below.

**`deploy.user` keeps its key.** A CI runner cannot touch a hardware key. When `deploy.user` is in the profile or on the host, the drop-in ends with:

```sshconfig
Match User deploy
	PubkeyAcceptedAlgorithms +sk-ssh-ed25519@openssh.com
```

A list that starts with `+` is appended to sshd's built-in default set (sshd_config(5)), and the default already contains `sk-ssh-ed25519@openssh.com`. So inside the `Match`, the deploy account's set should come out as exactly the default, whatever key types or certificates its keys use, without vps-ready writing the default list itself. A `Match` block in an included file ends at the end of that file (sshd_config(5); OpenSSH's own `servcfginclude.sh` test), so it cannot swallow the rest of `sshd_config`.

Before the PR merges, a VM check on all five releases captures the full `sshd -T -C user=<u>,host=<h>,addr=<a>` output for the admin and for the deploy account, before and after the drop-in, and diffs them. The only differences allowed are `pubkeyacceptedalgorithms` (and `pubkeyauthoptions` with `pin`) for the admin; the deploy account's output must not change at all. **If the `+` form does not restore the default** on some release, the fallback there is an explicit list: the deploy account's `pubkeyacceptedalgorithms` row becomes the one allowed difference, and the plan refuses while a deploy key's type (a certificate type, or ECDSA P-384 or P-521, for example) is outside that list. The deploy account's keys are already `restrict`ed (and optionally forced to one command), which is why it alone is exempt.

This narrows an M3 invariant: `ssh.server` "never writes ... crypto lists" ([the M3 plan](m3-plan.md)), enforced by the unit test `never_writes_ports_listeners_groups_methods_or_crypto`. With `security_keys = "required"` it writes `PubkeyAcceptedAlgorithms`, and only then; the test changes to allow exactly that keyword under that param.

**Refused at plan time when `PubkeyAcceptedAlgorithms` would change:**
1. The plan's admin has no `sk-` key in `authorized_keys` (on the host or in the plan).
2. **The admin has only one `sk-` key** and `single_security_key` is not set. A lost or broken key then means console recovery. The message says to register a second key (a spare kept elsewhere) and to log in with it once before applying, since an untested spare is no spare. With `pin = true`, both keys must have been made with `ssh-keygen -O verify-required` and have a PIN set, or sshd refuses them. The other way out is `single_security_key = true`, to accept the risk.
3. **The applying session did not log in with a security key.** sshd logs `Accepted publickey for admin from ... ssh2: ED25519-SK SHA256:...` for every login. vps-ready finds that line in the journal for the session's sshd process: matched on the current `_BOOT_ID`, the process's `_PID`, a timestamp after the process's start time (from `/proc/<pid>/stat`, so a reused PID cannot match an older line), and `_COMM` of `sshd-session` on OpenSSH 9.8 and later (Debian 13, Ubuntu 26.04) or `sshd` before. The message gives the command to log in with the key first. As with `ssh_via`'s refusal 3, this is the precondition, not the proof.
4. No SSH session (the console, cloud-init), or `--deadman=off`.
5. `export cloud-init` with `security_keys = "required"`: no session can prove a key at first boot. The export says to apply it after the first login.
6. The journal line cannot be found (journald not persistent and the line rotated, or no permission). A refusal, not a note: guessing here is a lockout.

**A note, not a refusal:** every other account that can log in by SSH (an `authorized_keys` file, a login shell, not `deploy.user`) and has no `sk-` key is listed: "after this, these accounts cannot log in by SSH: ops, backup". Refusing would block hosts with service accounts that never log in.

**The confirm is the proof.** `security_keys` arms the timer, as every `ssh.server` change does. The confirm must come from a new login, as the plan's admin, after the change went live. Under the new drop-in, sshd accepts nothing but a security key for that user, so a successful confirm means one works. No new refusal kind is needed. The printed confirm line adds `-o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_sk` as a hint, with a note that the file name is the user's.

**Verify.** `ssh.server`'s per-admin effective check (`verify_user`, which runs `sshd -T -C` for the admin) also checks `pubkeyacceptedalgorithms` (and `pubkeyauthoptions` with `pin`), and for the deploy account that the exemption holds.

**Never remove the last working login path.** `user.admin` never removes key lines, so the non-`sk` keys stay in `authorized_keys` and work again after a rollback or with `security_keys = "allowed"`. The console-password note from `ssh_via` is shown here too.

**Audit:** `SSH-010` (low), "Admin logins need a security key", a new check kind `sshd_effective_for` (`sshd -T -C` per sudo user). Skipped when no sudo user has an `sk-` key, so no host gains a failure from it. Fix: `ssh.server`.

**TOTP is not in M7** (decision 15). It needs a third-party PAM module, `KbdInteractiveAuthentication yes`, `AuthenticationMethods publickey,keyboard-interactive:pam`, a per-user secret on the host and a correct clock. A mistake in the PAM stack can refuse every login, including the console's. A security key is the stronger second factor and changes one sshd keyword.

### v1.0: what stable means

1.0.0 is a promise about what an upgrade within 1.x will not break. `docs/stability.md` states it; in short:

| Surface | Stable in 1.x | Allowed in a minor release |
|---|---|---|
| Profile format | `schema = 1`: every key and value valid in 1.0 parses the same in every 1.x | New optional params and modules, new values for an enum param |
| Built-in profiles | Never gain a module that needs the timer; never drop a module | A safer value for an existing setting, in the release notes |
| CLI | Commands, flags and their meaning; a plain `apply` still selects only `kernel.sysctl` and `updates.auto` | New commands and flags |
| Exit codes | 0 success, 1 audit failed / rolled back / drift, 2 error, 3 rollback incomplete, 4 pending, 130 interrupted | New codes only for new commands |
| JSON output (`audit`, `plan`, `history`, `modules`) | Existing fields keep name and type | New fields; consumers must ignore unknown ones |
| `detect --json` | Not stable (facts grow and change shape) | Anything, in the release notes |
| Control IDs | An ID keeps its meaning; a retired ID is never reused | New controls; a severity change, in the release notes |
| Journal | A 1.x binary reads and rolls back every transaction written by 0.7.0 or later | New record kinds; an older binary refuses them by name instead of guessing |
| Files on the host | Paths under `/etc/vps-ready`, `/var/lib/vps-ready` and the drop-in names | New files |

**Not yet stable in 1.0.** The surfaces added last have had the least use, so `docs/stability.md` lists them as provisional: `drift --json`, the SARIF layout (locations, fingerprints, run IDs), the shape of `config.toml`, `net.tunnel`'s params, and `ssh.server`'s `security_keys`, `pin` and `single_security_key`. They become stable after one minor release with no change to them, and the release notes say when.

**A breaking change to the profile format** would be a 2.0 matter and gets its own plan then; 1.0 promises nothing about 2.x.

**Deprecation.** A flag, param or command to be removed warns for at least one minor release, with the replacement, before a major release removes it.

**MSRV.** It matters only to `cargo install` and `sshd-config` users; release binaries are static. Policy: raised only in a minor release, to a Rust stable at least six months old, and named in the release notes. The CI check stays.

**Distro support.** A release stays supported for as long as its distro gives it free security updates: Ubuntu's standard support (not ESM) and, for Debian, Debian LTS, which follows the end of regular security support by about two years. Debian 12's regular security support ended in June 2026 and its LTS runs to June 2028, so Debian 12 stays. Support also needs the vendor repositories the modules use (Docker, Caddy, Tailscale, Cloudflare) to still publish for the release; when one stops, its module becomes not applicable there, with a note. A release leaves the list in a minor release, announced one release ahead. Ubuntu 22.04's standard support ends in 2027, so 1.x drops it in a minor release then.

**Journal format.** The `begin` record already carries the writer's version. From v0.7.0 it also carries `format: 1`, and a binary that meets a higher format refuses that transaction with "written by vps-ready X; use that version or newer", instead of failing on an unknown record kind.

**Before tagging 1.0.0:**
- Every piece above shipped in a 0.x release.
- **Real use:** the last 0.9.x ran on the maintainer's own hosts for at least four weeks, with `net.tunnel` and `security_keys = "required"` in use on at least one of them. cloudflared must go through a real unattended upgrade in that time; for the other vendor packages, a downgrade followed by an unattended upgrade is enough. Then `1.0.0-rc.1`, for at least two weeks. A breaking change, or a fix that changes a stable surface, in either period restarts its clock.
- A review of every module param, flag and control title, since 1.0 freezes their names; renames happen in 0.9.x.
- Journal fixtures from 0.7.0 onward read and roll back in a layer 1 test.
- All VM cycles pass on all five releases, and the manual release gates (Tailscale, the tunnel) pass.
- `cargo-fuzz` targets for the `sshd-config` parsers (`sshd -T` output, `sshd_config` with its Includes) exist, have run for a while without a crash, and run in CI on a schedule.
- `docs/stability.md` exists and the site links it from the install page.

Not gates: SLSA L3, new distro families, a paranoid profile.

### Facts

- `cloudflared --version` when installed; whether a cloudflared unit other than ours exists; `config.yml` or `config.yaml` in `/etc/cloudflared` or `/usr/local/etc/cloudflared`; a listener on `127.0.0.1:20241`; the nameservers in `/etc/resolv.conf`.
- The SSH session's login method: the `Accepted publickey` line for the session's sshd process, from the journal, bound by boot ID, PID, process start time and command name, parsed for the key type.
- `sshd -T -C user=<u>,host=<h>,addr=<a>` per sudo user, for `SSH-010` and verify.
- Accounts that can log in by SSH, with the types of their keys, for the security-key note.

### Resources and reloads

No new resource kinds. `net.tunnel` is `File`s (the units, the origin), `apt_source`, `Package` and `Service`s; `config.toml` is a `File`. `Reload::DaemonReload` before the units' `Service`s if the engine does not already order it. The journal's new `format` field is optional when read, so older journals read as before.

### Changes to earlier docs

- `README.md`: the platforms table (RHEL and Alpine "on demand", not "v0.7"); the roadmap line (M7 is the tunnel, depth and v1.0); `audit` formats; the modules table gains `net.tunnel`.
- `architecture.md`: `drift` and `config.toml` as built, `state.json` dropped; `src/report` formats; `schemars` as a dependency; the registry order; OpenRC and firewalld no longer "M7".
- `decisions.md`: D9 (distro order) becomes "on demand, Rocky and Alma first"; D19's "CrowdSec later" becomes "if asked for"; new decisions for remotely-managed tunnels only and for the 1.x stability promise.
- `scope.md`: backups move to non-goals, with the pairing note below; the wedge's "backups" removed.
- `security-baseline.md`: the `ops.backup` row marked out of scope; FIDO2 marked as built, TOTP as deferred; the order's step 7 gains the tunnel.
- `m6-plan.md`: the tunnel section points here.
- `m3-plan.md`: `ssh.server`'s "never writes crypto lists" invariant gains "except `PubkeyAcceptedAlgorithms` under `security_keys = "required"`", with the matching change to its unit test.
- `testing.md`, `release.md`: the new cycles and the manual tunnel gate.

**Backups, out of scope.** vps-ready hardens and then gets out of the way; backups need storage, credentials and a restore story that belong to a backup tool. The docs gain a short "Pairing with a backup tool" page:
- Back up the app's data, the profile file you apply, and `/etc/vps-ready/config.toml`.
- The secrets the profile points to are not in either file: the tunnel token file, a Tailscale auth key, `/etc/wireguard/wg0.key`. Keep them only in the backup tool's encrypted store, or plan to re-create them (a new tunnel token, a new WireGuard key and updated client configs).
- Rebuild the host from the profile (`export cloud-init`) rather than restoring `/etc`, and never restore `/var/lib/vps-ready` onto another host.

### Not in M7

| Idea | M7 | When |
|---|---|---|
| Rocky and Alma, Fedora, Alpine (with dnf, apk, firewalld, OpenRC adapters, `.rpm`, `.apk`) | Debian and Ubuntu | On demand; Rocky and Alma first if asked |
| Tailscale Funnel as a tunnel provider | Cloudflare only | If asked for; `provider` is ready for it |
| Locally-managed tunnels, cloudflared config files | Remotely managed, token only | Not planned (account-wide `cert.pem`) |
| Caddy DNS challenge behind the tunnel (end-to-end TLS) | HTTP on loopback | If asked for; needs a Cloudflare API token, a second secret |
| Some sites behind the tunnel, others public | One mode per host | If asked for |
| SSH through the tunnel (`cloudflared access`) | Never set up by vps-ready | Not planned: SSH goes through the VPN |
| Limiting the connector's loopback ports with a cgroup-matched firewall rule | `IPAddressDeny=` for non-loopback ranges, the note | If loopback routes prove a real risk |
| TOTP | Security keys | Not planned unless asked for; see above |
| auditd | | 1.x, opt-in only, never in a built-in profile |
| CrowdSec | fail2ban's `sshd` jail | If asked for: it overlaps the jail and adds a third-party service with a shared blocklist |
| Backups | Documented pairing | Out of scope |
| A `paranoid` profile | `private` plus `security_keys` | After 1.0, if the opt-in pieces add up to one |
| `drift --fix`, a drift timer, notifications | `drift` and the printed `apply` | If asked for |
| Security keys in the wizard | Profile only | If asked for |
| SSH certificates (a user CA) | Keys | If asked for |
| Nightly real-cloud runs | A manual `workflow_dispatch` run before each release | Decided (20) |
| `ratatui` plan view | Plain text | As in M4 |

## Testing

**Layer 1:**
- `net.tunnel`: the apt source (suite `any`) and embedded key fingerprint; the origin file; the connector unit, the path unit and its service (`insta`), with `--edge-ip-version auto` on an IPv6-only fixture and `IPAddressAllow=` from `resolv.conf` fixtures (a link-local resolver with a zone ID, stripped; Tailscale's `100.100.100.100`; Azure's `168.63.129.16`); the container note; the token path appears only in `LoadCredential=`, and the token never in any output (a test writes a marker token and greps every byte the engine wrote); key-file checks (group or other bits, symlink, not root's) refused; no `token_file` plans the install and the note; an old `cloudflared` refused; a listener on port 20241 refused; a hand-made `cloudflared.service` not applicable; export refuses `token_file`; rollback removes the units and keeps the package.
- The wizard's token file: written with `O_EXCL` and 0600 before the plan, never a resource, and its bytes absent from the journal.
- `deploy.proxy` `behind_tunnel`: the Caddyfile (`insta`); no DNS note; the "drop 80 and 443 from `allow`" note; the "nothing forwards" note; switching modes.
- Journal `format`: written from v0.7.0; a higher format refused by name; fixtures from each 0.x since 0.7.0 roll back.
- `config.toml`: resolved with defaults written out, merged per module, the resolved `ssh_via` after step 2 and none after step 1; written in the transaction and restored by rollback; no secret content.
- `drift`: none after apply; a hand edit, a runtime sysctl, a stopped service (through verify), each reported with module and transaction; a session refusal becomes a note and the module is still compared; a host-state refusal counts as drift; changed resolvers; exit codes; `--json`; no `config.toml` with and without journal transactions; a partial `config.toml` lists the unrecorded modules and exits 2; an apply on a converged host with a missing or partial `config.toml` plans writing it.
- JSON Schema: every built-in and test profile validates; a typo fails; every registered module has an entry; the schema snapshot changes only with a params change.
- SARIF: validates against the SARIF 2.1.0 schema; rules for every control; `startLine`, `automationDetails.id` and `primaryLocationLineHash` stable across runs; no pass or skip results. JUnit: parses; counts match the text report.
- `security_keys`: the drop-in with and without the `Match` block (`insta`); refusals 1 to 6, each from a fixture (journal lines for `ED25519`, `ED25519-SK`, `ECDSA-SK`, from `sshd` and `sshd-session`, a reused PID with an older line, a line from another boot, rotated away); the other-accounts note; `pin`; `SSH-010` skipped without `sk-` keys.

**Layer 2 (containers):**
- `net.tunnel` installs from Cloudflare's real repository on all images, and `cloudflared --version` is at least 2025.4.0.
- With a dummy token file, starting the unit fails within `TimeoutStartSec` (no `READY=1`), and the apply reports the tunnel as the cause and rolls back. cloudflared accepts `/etc/vps-ready/cloudflared.yml` and logs no config error.
- **Upgrade restart:** install the previous version from the repository (`apt-get install cloudflared=<previous>`) and keep the connector unit active without an account: a test-only drop-in replaces `ExecStart` with a long-lived cloudflared subcommand that needs no tunnel (picked in the PR), wrapped so that `READY=1` is sent only after a few seconds. The unit stays `Type=notify`, so `try-restart` blocks about as long as in production, which is what exposes the race. Then upgrade with `apt-get install cloudflared`, and check that the restart service ends successfully and `/proc/<MainPID>/exe` has the inode of the new `/usr/bin/cloudflared`. Run it ten times in a row, since the race depends on timing.
- The restart script: it passes `sh -n`, and with the binary held stale (a test-only bind mount) it retries five times and fails with its message.
- `unattended-upgrade --dry-run` lists the origin; rollback removes the source.
- Caddy behind the tunnel answers `curl -H 'Host: app.example.com' -H 'Cf-Connecting-Ip: 192.0.2.7' -H 'X-Forwarded-For: 198.51.100.9' http://127.0.0.1/`; the upstream (a small echo server) sees `X-Forwarded-For: 192.0.2.7` only; `X-Forwarded-Proto: http` gets a 308; nothing listens on a public address.

**Layer 3 (VMs), the connector's address filter:** on all five releases, add a dummy interface with a private address (`10.99.0.1/32`) and a listener on it. A process started with the connector unit's own `IPAddressDeny=` and `IPAddressAllow=` (`systemd-run --wait --pipe -p DynamicUser=yes` with the properties read from the installed unit) cannot connect to `10.99.0.1` and can connect to a loopback listener; and verify reports no filter warning. Containers are not used for this, since they may not enforce it.

**Layer 3 (VMs), security keys:** a `security-keys` cycle on all five releases. No hardware key is needed. The authenticator is decided up front: OpenSSH's software test authenticator (`sk-dummy.so`, from `regress/misc/sk-dummy` in the OpenSSH source), built in the job from each release's own `openssh` source package so it matches that release's middleware API, and loaded on the client side with `SSH_SK_PROVIDER`. The cycle checks:
1. Refusal 3 from a session with a plain key; refusal 2 with one `sk-` key; the apply from a session with an `sk-` key and two registered.
2. During the window, a new plain-key login as admin is refused; a confirm from a new `sk-` login succeeds; the deploy account still logs in with its plain key.
3. Not confirmed: at the deadline, plain keys work again.
4. The full `sshd -T -C` diff for admin and deploy, after a reboot too.

If the build of the test authenticator fails on a release, step 2 for that release moves to the manual release gate with a real key, and the release PR says so.

**Release gate (manual):** a tunnel needs a Cloudflare account and a domain. Before tagging a release with `net.tunnel`, the maintainer creates a tunnel, applies `private` with `net.tunnel` and `deploy.proxy` on one Debian 13 and one Ubuntu 24.04 VM, and then:
- loads the site through Cloudflare, over `http://` (redirected) and `https://`;
- checks that the app sees the visitor's address (and only it, in `X-Forwarded-For`) and the right `Host`;
- checks from outside that no TCP port answers (with Tailscale for SSH);
- adds a route to a listener on a private address of the VM and checks the visitor gets an error, not the page;
- reboots, and records it all in the release PR.

## PR sequence

1. **`docs: plan M7`** (this document).

Wave 1, v0.7.0:

2. **`feat(modules): net.tunnel`**: the vendor source and key with its weekly check, the origin file, the connector and path units, verify through `ready`, the `SSH-009` caveat, the layer 2 cycle. *Parallel with 3 and 5.*
3. **`feat(modules): deploy.proxy behind_tunnel`**. *Parallel.*
4. **`feat(cli): the tunnel in the wizard and the private profile`** (needs 2, 3 and M6's wizard).
5. **`feat(engine): journal format field`** and the start of the compatibility fixtures. *Parallel.*

Wave 2, v0.8.0:

6. **`feat(audit): SARIF and JUnit output`**. *Parallel with 7 and 9.*
7. **`feat(config): record the applied profile in config.toml`**. *Parallel.*
8. **`feat(cli): drift`** (needs 7).
9. **`feat(config): JSON Schema for profiles`**. *Parallel.*
10. **`feat(platform): Ubuntu 26.04`**, with the sudo-rs checks. *Parallel.*

Wave 3, v0.9.0:

11. **`feat(modules): security-key logins in ssh.server`** (needs 10): starts with the `Match` VM diff; then the param, refusals, `SSH-010`, verify, the VM cycle.

Wave 4, v1.0.0:

12. **`test(sshd-config): fuzz targets`**. *Parallel with 13; can start any time.*
13. **`docs: stability policy`**: `docs/stability.md`, and the name review's renames (in a 0.9.x code PR of their own if they touch code).
14. **`docs(site): tunnel, drift, security keys, stability`**: the guides and the doc changes above. Each wave updates the pages it touches; this PR finishes them.
15. **`chore: release v1.0.0-rc.1`**, then **`chore: release v1.0.0`**, after the real-use and RC periods above.

Waves: {2, 3, 5} → 4 → {6, 7, 9} → 8 → 10 → 11 → {12, 13} → 14 → 15. Each wave is a release; a wave that slips does not hold the next one, except wave 4, which needs all of them.

## Fact check

Checked against upstream docs and sources while writing this plan; items marked VM are checked in the PR that needs them.

| Claim | Source |
|---|---|
| Debian and Ubuntu install: key `cloudflare-main.gpg`, repository `https://pkg.cloudflare.com/cloudflared`, suite `any`, component `main`; per-codename suites also exist | Cloudflare package repository page (pkg.cloudflare.com) |
| `Origin: cloudflared`, `Codename: any`; amd64 and arm64; version 2026.11.1 on 2026-11-19; the key is RSA 4096, created 2025-10-23 | The repository's `Release` and `Packages` files and the key, downloaded |
| The package's `postinst` makes a symlink and a marker file and restarts nothing | cloudflared source at 2026.11.1, `postinst.sh` |
| `service install <token>` writes the token to a file under `/etc/cloudflared` and passes `--token-file`; its unit is `cloudflared.service` with `Type=notify`, `TimeoutStartSec=15`, no `User=` and no sandboxing | cloudflared source at 2026.11.1, `cmd/cloudflared/linux_service.go` |
| `READY=1` is sent only after the first connection is registered | cloudflared source at 2026.11.1, `cmd/cloudflared/tunnel/cmd.go` (`notifySystemd`) |
| Without `--config`, the config search covers `/etc/cloudflared` and `/usr/local/etc/cloudflared` | cloudflared source at 2026.11.1, `config/configuration.go` |
| An empty config logs an error line at start; `no-autoupdate: true` in the file is accepted | VM (layer 2) |
| `--token-file` / `TUNNEL_TOKEN_FILE` need 2025.4.0 and work for remotely-managed tunnels only; `--edge-ip-version` defaults to 4; `--protocol auto` prefers QUIC and falls back to HTTP/2; the updater does nothing for package-manager installs | Cloudflare docs, tunnel run parameters |
| Remotely managed: created in the dashboard, configuration at Cloudflare; locally managed: created with `cloudflared tunnel create`, configuration in a local directory | Cloudflare docs, tunnel useful terms |
| Outbound port 7844 TCP and UDP to the edge; no inbound port | Cloudflare docs, tunnel with firewall |
| `httpHostHeader` defaults to empty | Cloudflare docs, origin parameters. That an empty value passes the visitor's `Host` through: release gate |
| Metrics server on loopback (20241 to 20245 by default); `/ready` returns 200 with at least one registered connection, 503 otherwise; `cloudflared tunnel ready` | Cloudflare docs, tunnel metrics; cloudflared source, `metrics/readiness.go` |
| The sandboxing lines work for the connector; the restart converges after a dpkg upgrade | VM (layer 2) |
| `IPAddressDeny=` is enforced with cgroup BPF, and without it systemd only warns | systemd.resource-control(5); VM (layer 3; containers may not enforce it) |
| A `+` list in `PubkeyAcceptedAlgorithms` is appended to the default set, which already holds `sk-ssh-ed25519@openssh.com` | sshd_config(5); VM (the `sshd -T -C` diff) |
| dpkg hard-links the old file to `.dpkg-tmp` before renaming the new one into place | VM (layer 2) |
| `LoadCredential=` added in systemd 247, readable by the unit's user including a `DynamicUser`; `${CREDENTIALS_DIRECTORY}` in `ExecStart` | systemd.exec(5) |
| `PathChanged=` triggers when a file open for writing is closed; path units use inotify | systemd.path(5); the restart converges whichever event fires |
| systemd versions: Debian 12 252, Debian 13 257, Ubuntu 22.04 249, Ubuntu 24.04 255, Ubuntu 26.04 259 | Debian and Ubuntu package indexes; Ubuntu 26.04 release notes |
| `http://` site addresses turn off automatic HTTPS for the site; `default_bind`; `trusted_proxies`; `client_ip_headers`; `auto_https` values | Caddy docs, Automatic HTTPS; Caddy docs, global options |
| `header_up X-Forwarded-For {client_ip}` replaces the header Caddy would otherwise append to | Caddy docs, `reverse_proxy` directive; VM (layer 2) |
| `ecdsa-sk` and `ed25519-sk` key types and the touch requirement since OpenSSH 8.2; `verify-required` since 8.4 | OpenSSH 8.2 and 8.4 release notes |
| OpenSSH versions: Debian 12 9.2, Debian 13 10.0, Ubuntu 22.04 8.9, Ubuntu 24.04 9.6, Ubuntu 26.04 10.2; `sshd-session` from 9.8 | Debian and Ubuntu package indexes; OpenSSH 9.8 release notes; Ubuntu 26.04 release notes |
| Ubuntu 26.04 uses sudo-rs as `sudo`; the original stays installable as `sudo.ws` | Ubuntu 26.04 release notes; the sudo-rs behaviors listed above: VM |
| `Match` in an included file ends at the end of that file | sshd_config(5); OpenSSH regression test `servcfginclude.sh`; VM (the `sshd -T -C` diff) |
| The `Accepted publickey ... ED25519-SK` line, its `_PID`, `_COMM` and `_BOOT_ID` on each release | VM (fixtures captured in PR 11) |
| `sk-dummy` software authenticator in OpenSSH's regression tests, loaded through `SSH_SK_PROVIDER` | OpenSSH source, `regress/misc/sk-dummy`; VM |
| SARIF 2.1.0 only; a result needs a location; `security-severity` bands; only `primaryLocationLineHash` is used; `automationDetails.id`; per-run limits | GitHub docs, SARIF support for code scanning |
| Debian 12 regular security support ended June 2026, LTS to June 2028; Ubuntu 22.04 standard support ends 2027 | Debian security and LTS pages; Ubuntu release cycle page |

## Decisions

1. **Releases: v0.7.0 the tunnel and the journal `format` field, v0.8.0 `drift`, `config.toml`, SARIF/JUnit, the JSON Schema and Ubuntu 26.04, v0.9.0 security keys, then v1.0.0.** Accepted: the owner's split, with the schema next to `config.toml`, the journal field early, and auditd out. The owner later moved Ubuntu 26.04 from v0.9.0 into v0.8.0; it still lands before security keys.
2. **Cloudflare Tunnel, remotely-managed tunnels only, with the trust model stated.** Accepted: the host needs only a token for one tunnel, not the account-wide `cert.pem`; the account's control over routes is stated in the plan's note, the docs and `SSH-009`'s finding.
3. **vps-ready's own connector unit with `LoadCredential=`, `DynamicUser=yes`, sandboxing, `IPAddressDeny=` (noted when not enforced) and its own config file,** not `cloudflared service install`. Accepted: Cloudflare's unit also uses `--token-file` now, but runs as root without sandboxing and under the name the dashboard's own instructions use.
4. **The token only through a root-only file the user creates (or the wizard writes outside the transaction); without it, install only with a note; `export` refuses `token_file`.** Accepted: the same rules as Tailscale's auth key.
5. **cloudflared updates through unattended-upgrades (`origin=cloudflared,codename=any`), with a path unit, installed only with the connector, whose restart script waits for dpkg to finish, restarts, and compares the running binary's inode with the file, retrying up to five times.** Accepted: the connector faces the internet, the package does not restart it, and a single `try-restart` can race dpkg's rename.
6. **`Type=notify` start is the gate (`TimeoutStartSec=30`), `cloudflared tunnel ready` the read-back, on a fixed loopback metrics port; a tunnel failure rolls back the whole transaction, including the wizard's SSH hardening, with an error naming the tunnel.** Accepted: one transaction stays whole.
7. **`deploy.proxy` `behind_tunnel`: plain HTTP on loopback, TLS at the edge, an HTTPS redirect on `X-Forwarded-Proto: http`, the visitor's address from `Cf-Connecting-Ip` only, and `X-Forwarded-For` rewritten to that one address.** Accepted: no second secret, no port to open, and no visitor-controlled address.
8. **No safety timer for `net.tunnel`,** and no new built-in profile; the wizard offers it only with `private`. Accepted: it cannot change the SSH path vps-ready manages; the account-level risk is handled by the trust model, not the timer.
9. **`config.toml` resolved (no `extends`, defaults written out), recording what was applied (the resolved `ssh_via`), merged per module, written in the same transaction.** Accepted: drift reports only what an apply did, and rollback keeps it in step.
10. **`drift` is a read-only plan plus each module's `verify` against `config.toml`, with session refusals as notes and no `state.json`;** host-state refusals count as drift; exit 1 on drift, exit 2 for a host applied before 0.8.0 or with modules not recorded; a missing or partial `config.toml` makes `apply` plan a change; no `--fix`. Accepted: one comparison path, the plan's, already tested.
11. **The JSON Schema in M7, generated with `schemars`.** Accepted: it is the published contract of `schema = 1` that 1.0 freezes.
12. **`audit --format text|json|sarif|junit`, with `--json` kept.** Recommended over a separate flag per format.
13. **SARIF with the host as a logical location, a synthetic `<host>/<control>` physical location at line 1, one `automationDetails.id` per host, `primaryLocationLineHash` fingerprints, and fail and unknown results only.** Accepted: code scanning shows the results, keeps hosts apart, and closes fixed ones.
14. **`security_keys = "required"` accepts only the `sk-` types. It is refused unless the admin has two `sk-` keys (or `single_security_key = true`) and the applying session logged in with one, found in the journal by boot, PID, start time and command. The timer's new-login confirm is the proof. `deploy.user` is exempt through a `Match` block with `PubkeyAcceptedAlgorithms +sk-ssh-ed25519@openssh.com`, which restores the default set (an explicit list and a key-type refusal if the VM diff shows otherwise); this narrows M3's "never writes crypto lists"; other accounts without `sk-` keys are listed in a note; verify checks the new keyword; `pin` is opt-in; CI uses OpenSSH's `sk-dummy`.** Accepted as a set. The `Match` VM diff decides between the `+` form and the explicit-list fallback.
15. **Defer TOTP.** Accepted: a PAM mistake can refuse every login, including the console's, and security keys cover the need.
16. **auditd after 1.0, opt-in only, never in a built-in profile.** Accepted: an opt-in module is additive in 1.x, so it need not land before the freeze, and its value on a single VPS without log shipping is small.
17. **CrowdSec deferred; backups out of scope, with a pairing page.** Accepted: CrowdSec overlaps the fail2ban jail and adds a third-party service; backups need storage and credentials vps-ready should not hold.
18. **No `paranoid` profile in M7.** Accepted: its pieces arrive as opt-in params; a profile can follow once they add up to one.
19. **Ubuntu 26.04 in M7, scoped as re-checking the M3 and M6 session and confirm assumptions under sudo-rs, landing before security keys.** Accepted: 1.0 should support the current LTS, and sudo-rs is the change most likely to break a lockout guarantee.
20. **Real-cloud runs are a `workflow_dispatch` run before each release, not nightly.** They cost money and need a provider API token in a protected environment. The run exports a profile, boots a server, checks from outside that only the expected ports answer, and destroys it.
21. **The 1.x promise as in [v1.0](#v10-what-stable-means):** `schema = 1` additive only; CLI and exit codes stable; JSON additive, with `detect --json` excluded; the newest surfaces provisional until one minor without change; journal `format: 1`; deprecation with one minor of warning; MSRV raised only in a minor to a Rust at least six months old; distro support for as long as Ubuntu standard support or Debian LTS; no promise about 2.x. Accepted as a set.
22. **1.0.0 after four weeks of real use of the last 0.9.x, then `1.0.0-rc.1` for two weeks, with no breaking change, after a review of every name and with fuzz targets running.** Accepted: names freeze at 1.0, so they are checked once on purpose, and time on real hosts finds what tests do not.
