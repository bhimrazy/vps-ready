# M7 plan: web through a tunnel, depth, and v1.0

> **Status: proposed (2026-11-19).** Nothing below is built yet. The owner decides on each recommendation in [Decisions](#decisions-for-the-owner).

M7 lets a web app run with no public port through a Cloudflare Tunnel, adds drift detection, CI-friendly audit output and security-key SSH logins, and then makes the tool stable as v1.0.

It has three parts, in this order:

1. **`net.tunnel`**: Cloudflare Tunnel, with `deploy.proxy` behind it on loopback. With it, a host running a web app can close 80 and 443 too, so the `private` profile reaches zero public TCP ports even with a website.
2. **Depth**: `drift` with `/etc/vps-ready/config.toml`, SARIF and JUnit output for `audit`, a JSON Schema for profiles, and security-key (FIDO2) SSH logins.
3. **v1.0**: what "stable" means for the profile format, the CLI, exit codes and the journal, and what must be true before tagging 1.0.0.

New distro families (Rocky and Alma, Fedora, Alpine) are not in M7. Earlier docs place them in M7; they now come on demand (see [Not in M7](#not-in-m7)). Ubuntu 26.04, a new release of a family already supported, is in.

This plan assumes M6 is complete, including the `private` profile. If v0.6.0 ships after M6's second wave, its later waves come first as v0.6.x.

Only one piece changes the SSH path: security keys. It gets the same lockout care as `ssh_via`. The tunnel never carries SSH, so it cannot lock anyone out; a broken tunnel takes the website down, and the apply that set it up rolls back.

## Decisions

### Scope and releases

| Release | Piece | Changes | Safety timer |
|---|---|---|---|
| v0.7.0 | `net.tunnel` | Cloudflare's apt source and key, `cloudflared`, an unattended-upgrades origin, and `vps-ready-cloudflared.service`, which runs the connector with a token from a root-only file | no |
| v0.7.0 | `deploy.proxy` `behind_tunnel` | Caddy serves plain HTTP on loopback only; no certificates, no public 80 or 443 | no |
| v0.7.0 | `private` profile and wizard | a tunnel instead of 80 and 443 | as in M6 |
| v0.8.0 | `/etc/vps-ready/config.toml` | every apply records the profile it applied | as the apply |
| v0.8.0 | `drift` | nothing; reports what changed since the last apply | |
| v0.8.0 | `audit --format sarif\|junit` | nothing; new output formats | |
| v0.8.0 | JSON Schema | nothing on the host; `vps-ready schema` and a release asset | |
| v0.9.0 | `ssh.server` `security_keys` | the sshd drop-in accepts only security-key logins (with an exemption for `deploy.user`) | yes |
| v0.9.0 | Ubuntu 26.04 | data tables, the test matrix | |
| v1.0.0 | Stability | a journal format field, `docs/stability.md`, a review of every name before it freezes | |

The split follows the owner's suggestion, with two changes. The JSON Schema moves into v0.8.0 with `config.toml`, since both describe the same format and the schema should exist for a release before 1.0 freezes it. auditd is not in v0.9.0 (decision 16): after 1.0 a new opt-in module is an additive change, so it does not need to land before the freeze. SARIF and JUnit do not depend on anything else, so they can move into v0.7.0 if the tunnel slips.

The registry order becomes `user.admin`, `ssh.server`, `net.tailscale`, `net.wireguard`, `net.tunnel`, `deploy.docker`, `firewall.inbound`, `ssh.bruteforce`, `kernel.sysctl`, `updates.auto`, `deploy.proxy`, `deploy.user`. `net.tunnel` comes before `deploy.proxy`, which reads whether a tunnel is planned.

### Web through a tunnel: `net.tunnel`

```toml
[modules."net.tunnel"]
provider = "cloudflare"                 # the only value in M7
token_file = "/root/cloudflared-token"  # optional
auto_update = true                      # default
```

**What it is.** `cloudflared` on the host opens outbound connections to Cloudflare's edge, and the edge sends requests for the user's hostnames back through them. No inbound port is needed: Cloudflare's firewall page asks only for outbound port 7844 (TCP for `http2`, UDP for `quic`), and our `established,related` rule covers the replies. `firewall.inbound` filters inbound traffic only, so nothing changes there.

**Remotely-managed tunnels only.** Cloudflare has two kinds:
- **Remotely managed:** created in the dashboard (or the API). Its routes (public hostname to local service) live at Cloudflare, and the connector needs only the tunnel's token.
- **Locally managed:** created with `cloudflared tunnel create`, which needs `cert.pem` from `cloudflared tunnel login`. That certificate can create and delete tunnels and DNS records for the whole account, so it is far more than a single host needs.

vps-ready supports the first only. It runs the connector; the user creates the tunnel and its routes in the dashboard, and the plan says what to enter there (below). vps-ready cannot see those routes.

**Install.** Cloudflare's repository through the M5 `apt_source` helper: `https://pkg.cloudflare.com/cloudflared`, suite `any`, component `main`, for every Debian and Ubuntu release. The repository also has per-codename suites; Cloudflare's own instructions use `any`, and its `Release` file lists amd64 and arm64. The binary key (`cloudflare-main.gpg`, RSA 4096, created 2025-10-23) is embedded with its fingerprint, and the weekly key check gains it. Then `Package cloudflared`.

**Updates.** With `auto_update = true`, `/etc/apt/apt.conf.d/52vps-ready-cloudflared` adds `Unattended-Upgrade::Origins-Pattern { "origin=cloudflared,codename=any"; };`. The repository's `Release` file says `Origin: cloudflared` and `Codename: any`, so `${distro_codename}` would never match. cloudflared's own updater does nothing for package-manager installs (Cloudflare's run parameters page), and the unit passes `--no-autoupdate` anyway.

**The unit, and where the token goes.** Cloudflare's `cloudflared service install <token>` writes `cloudflared.service` with the token in `ExecStart`, where `systemctl status` and `ps` show it. vps-ready writes its own unit instead:

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
LoadCredential=token:/root/cloudflared-token
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:20241 run --token-file ${CREDENTIALS_DIRECTORY}/token
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

- `--token-file` needs cloudflared 2025.4.0 or later; the repository has 2026.11.1 today. The plan refuses an installed `cloudflared` older than that (only possible with a pinned or hand-installed binary).
- `LoadCredential=` (systemd 247; Debian 12 has 252, Ubuntu 22.04 has 249) copies the root-only file into a directory only the service's user can read, and `DynamicUser=yes` makes that user a fresh unprivileged one. cloudflared never runs as root and never sees anything else of root's.
- The token is never in argv, the unit file, the journal, the plan or the profile; the profile holds only the path, and vps-ready never opens the file. The file must be a regular file owned by root with no group or other permissions, and not a symlink, as for `net.tailscale`'s `auth_key_file`.
- `Type=notify` matches the unit `cloudflared service install` writes; the sandboxing lines are checked against a running connector in the layer 2 cycle (QUIC, ICMP proxy warnings) and dropped one by one if they break it.
- `--edge-ip-version` defaults to `4`. On a host with no IPv4 default route, the unit gets `--edge-ip-version auto`, with a note.
- **No token file:** the module installs `cloudflared` and the update origin, plans no unit, and says "create a tunnel in the Cloudflare dashboard, save its token to a root-only file, set `token_file` and apply again". This mirrors `net.tailscale` without a key.
- **Not applicable** when a `cloudflared.service` (Cloudflare's own install) or another cloudflared unit exists. That is a hand-made setup; `deploy.proxy`'s `behind_tunnel` works with it.

**Verify.** `cloudflared tunnel --metrics 127.0.0.1:20241 ready`, retried for up to 30 seconds. It exits 0 once the connector has registered at least one connection with the edge (the `/ready` endpoint returns 200, 503 before). A bad token or blocked port 7844 fails verify, and the apply rolls back. The fixed metrics address keeps `ready` deterministic; it is on loopback, which `FW-003` does not count.

**What the plan prints**, so the dashboard side is right:

```
note: in the Cloudflare dashboard, give this tunnel a published route for each site:
        app.example.com  ->  http://127.0.0.1:80
      With deploy.proxy, Caddy answers on 127.0.0.1:80. Without it, point the
      route at your app's local address instead.
```

**Rollback** stops and disables the unit and removes it, the apt source, the key and the origin file. The package stays, as for every `Package`; the token file stays (it is the user's). The tunnel then shows as down in the dashboard; deleting it there is the by-hand step.

**Export.** `export cloud-init` refuses `token_file`, for the reason it refuses Tailscale's `auth_key_file`: user-data is readable through the metadata service. `net.tunnel` without `token_file` is exported; the first login sets the token and applies again.

**Tailscale Funnel** stays out of M7 (only `ts.net` names, three ports). `provider` exists from the start so that a second value later is additive.

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
		client_ip_headers Cf-Connecting-Ip X-Forwarded-For
	}
}

http://app.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

- **TLS ends at Cloudflare's edge.** The `http://` site address turns off Caddy's automatic HTTPS for that site (Caddy's Automatic HTTPS docs), so Caddy needs neither port 80 for the ACME challenge nor 443, and gets no certificate. The hop from cloudflared to Caddy is loopback. The redirect to HTTPS is the edge's ("Always Use HTTPS" in the dashboard), and the docs say so.
- **Loopback only.** `default_bind` keeps Caddy off public addresses, so even with `firewall.inbound` not applied, nothing listens publicly. `FW-003` then shows no web port.
- **Host header.** Caddy matches the site by `Host`. cloudflared's `httpHostHeader` is empty by default, which is expected to pass the visitor's hostname through; the layer 2 cycle checks it (with a local request carrying the `Host` header) and the release gate checks it end to end. If it does not, the plan's route note adds "HTTP Host Header: app.example.com".
- **Client addresses.** Every request reaches Caddy from `127.0.0.1`. `trusted_proxies` limited to loopback lets Caddy take the visitor's address from `Cf-Connecting-Ip`, so the app's logs and Caddy's `X-Forwarded-For` show the visitor, not the connector. Nothing else on the host can spoof it from outside, since only loopback is trusted.
- **Plan-time changes:** the DNS note ("app.example.com does not point here") is skipped, since the domain points at Cloudflare; the `firewall.inbound` note about 80 and 443 is skipped; a note when no tunnel connector is planned or running ("nothing forwards to Caddy yet: add `net.tunnel`").
- **Switching** `behind_tunnel` on or off rewrites the Caddyfile and reloads Caddy; it is one apply. Turning it off brings back automatic HTTPS, which needs 80 and 443 open, and the existing note says so.
- One mode per host: every site is behind the tunnel or none is (see Not in M7).

### Zero public ports, completed

| Setup | Public on the host |
|---|---|
| Tailscale for SSH, tunnel for the web | No inbound port |
| WireGuard for SSH, tunnel for the web | UDP 51820 only, which answers nothing without a valid handshake |
| A VPN for SSH, no tunnel, a web app | 80 and 443 (as in M6) |

**The `private` profile and the wizard.** The wizard's ports question, when the profile is `private` and the user adds a domain, gains one choice:

```
? How do visitors reach this site
  > Through a Cloudflare Tunnel (no public ports; DNS on Cloudflare)
    Directly, on ports 80 and 443 (Caddy gets the certificate)
```

The tunnel choice adds `net.tunnel` and `behind_tunnel = true`, and leaves `allow` empty. The token is asked hidden, written to `/etc/vps-ready/cloudflared-token` (0600; unlike Tailscale's one-off key it is needed at every start, so it stays) and set as `token_file`. Outside the `private` profile the question is not asked; a profile file can still combine the modules.

### Drift and `/etc/vps-ready/config.toml`

**`config.toml` records what was applied.** Every apply that changes something writes `/etc/vps-ready/config.toml` (0600, root) as a `File` resource in the same transaction, so a rollback, including the dead-man's, restores the previous one.
- **Resolved, not as written:** `schema = 1`, no `extends`, and each applied module's full params after the merge with its base profile. If a later release changes the built-in `web` profile, drift does not report a change nobody applied.
- **Merged per module:** `apply --module kernel.sysctl` replaces only that module's table. A module dropped with `enabled = false` stays in the file (vps-ready does not undo it), with its last params.
- It holds no secrets: Tailscale and the tunnel are given as paths, and authorized keys are public.
- `export cloud-init` keeps writing `/etc/vps-ready/profile.toml`; the first apply then writes `config.toml` like any other.

**`vps-ready drift`** is a read-only plan against `config.toml`:

```
$ sudo vps-ready drift
ssh.server  /etc/ssh/sshd_config.d/00-vps-ready.conf  changed since txn 20261203T101500Z
            -PasswordAuthentication no
            +PasswordAuthentication yes
kernel.sysctl  net.ipv4.conf.all.rp_filter  runtime 0, file 2
2 drifted. To restore: sudo vps-ready apply --profile /etc/vps-ready/config.toml
```

- Exit codes: 0 no drift, 1 drift, 2 error (as `audit`). `--json` lists each drifted resource with its module.
- **No `state.json`.** The plan already compares every resource with the host (file content, sysctl runtime values, service state, `wg0`'s runtime peers), so a hash store would repeat it and could itself go stale. The journal adds the one thing the plan lacks: when the file was last written, and by which transaction, from the newest `files/<n>.after` for that path.
- Notes do not count as drift. A module that is now not applicable (Docker removed) is reported as such, not as a change.
- Without `config.toml`: "nothing has been applied on this host yet" and exit 0.
- No `drift --fix`; the printed `apply` is the fix, behind the same plan, prompt and timer. No drift timer or notification in M7.

### JSON Schema for profiles

`vps-ready schema` prints a JSON Schema (draft 2020-12) for the profile format, generated with `schemars` from the same `deny_unknown_fields` structs, so it cannot drift from the parser. Each release attaches it as `vps-ready-profile.schema.json`, and the site serves it at a stable URL. A profile can name it on its first line (`#:schema <url>`) for editors that read that comment.

`schemars` is the one new dependency in M7, already listed as "later" in the architecture doc. Params that are parsed by hand into a newtype (`Domain`, `Upstream`, WireGuard keys) get a `pattern` or a description, not their full rules; the parser stays the authority.

### `audit` output: SARIF and JUnit

`audit --format text|json|sarif|junit`. `--json` stays as a short form of `--format json`. The exit code does not change with the format.

**SARIF 2.1.0**, the only version GitHub code scanning accepts:
- `tool.driver.rules`: every control in the catalog, with `id` (the control ID), `shortDescription` (title), `fullDescription` (why), `help` (the fix command), and `properties.security-severity`: high 8.0, medium 5.5, low 3.0, which fall in GitHub's high, medium and low bands.
- `results`: fail as `kind: fail` (level from severity), unknown as `kind: open`. With `--all`, pass as `kind: pass` and skip as `kind: notApplicable`.
- **Locations.** Code scanning shows a result only with at least one location, and these findings are about a host, not a source file. Each result gets a `logicalLocation` (the host name) and a `physicalLocation` whose URI is `<host>/<control ID>` under a `HOST` base. Code scanning then lists them, with a link to a file that does not exist; the docs say so. `partialFingerprints` come from the host name and control ID, so a re-run updates an alert instead of adding one.
- The PR checks the output against the SARIF 2.1.0 JSON Schema in a test, and with one upload to a scratch repository by hand.

**JUnit XML**, for CI systems that render test reports:
- `<testsuites name="vps-ready audit">`, one `<testsuite>` per area (SSH server, Firewall, ...), one `<testcase>` per control with `classname` the area and `name` "SSH-002 Password login is off".
- Fail is `<failure>` with the finding, unknown is `<error>` (the check could not run), skip is `<skipped>`, pass is an empty test case. JUnit consumers expect the whole suite, so every control is always listed, with or without `--all`.
- No schema check (JUnit has no formal one); a snapshot and a parse in the test.

### Security-key SSH logins (FIDO2)

OpenSSH has supported security keys since 8.2, with the key types `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`, and `verify-required` (a PIN on the key) since 8.4. Every supported release ships newer: Debian 12 has 9.2, Debian 13 has 10.0, Ubuntu 22.04 has 8.9 and Ubuntu 24.04 has 9.6. The server needs no hardware and no `libfido2`; only the client talks to the key. `user.admin` already accepts `sk-` key lines.

```toml
[modules."ssh.server"]
security_keys = "required"   # "allowed" (default: no change) or "required"
pin = false                  # true adds verify-required
```

**What changes in the drop-in:** `PubkeyAcceptedAlgorithms` lists only the two `sk-` types (and their `-cert-v01@openssh.com` forms); with `pin = true`, `PubkeyAuthOptions verify-required`. sshd already requires a touch by default. Passwords are already off (`SSH-002`), so a security key becomes the only way in for every user but the exemption below.

**`deploy.user` keeps its key.** A CI runner cannot touch a hardware key. When `deploy.user` is in the profile or on the host, the drop-in ends with:

```sshconfig
Match User deploy
	PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256
```

A `Match` block in an included file ends at the end of that file (sshd_config(5); OpenSSH's own `servcfginclude` test), so it cannot swallow the rest of `sshd_config`. Before the PR merges, a VM check confirms `sshd -T -C user=deploy,...` shows the exemption on all four releases and `sshd -T -C user=admin,...` does not. The deploy account's keys are already `restrict`ed (and optionally forced to one command), which is why it, alone, is exempt.

**Refused at plan time when `PubkeyAcceptedAlgorithms` would change:**
1. The plan's admin has no `sk-` key in `authorized_keys` (on the host or in the plan).
2. **The applying session did not log in with a security key.** sshd logs `Accepted publickey for admin from ... ssh2: ED25519-SK SHA256:...` for every login; vps-ready reads that line for the session's sshd process from the journal (`journalctl _PID=<pid>`). The message gives the command to log in with the key first. As with `ssh_via`'s refusal 3, this is the precondition, not the proof.
3. No SSH session (the console, cloud-init), and `--deadman=off`.
4. `export cloud-init` with `security_keys = "required"`: no session can prove a key at first boot. The export says to apply it after the first login.
5. The journal line cannot be read (journald not persistent and the line rotated, or no permission). A refusal, not a note: guessing here is a lockout.

**The confirm is the proof.** `security_keys` arms the timer, as every `ssh.server` change does. The confirm must come from a new login, as the plan's admin, after the change went live; under the new drop-in sshd accepts nothing but a security key for that user, so a successful confirm means one works. No new refusal kind is needed. The printed confirm line adds `-o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_sk` as a hint, with a note that the file name is the user's.

**Never remove the last working login path:** `user.admin` never removes key lines, so the non-`sk` keys stay in `authorized_keys` and work again after a rollback or with `security_keys = "allowed"`. The console-password note from `ssh_via` is shown here too.

**Audit:** `SSH-010` (low), "Admin logins need a security key", a new check kind `sshd_effective_for` (`sshd -T -C` per sudo user). Skipped when no sudo user has an `sk-` key, so no host gains a failure from it. Fix: `ssh.server`.

**TOTP is not in M7** (decision 15). It needs a third-party PAM module, `KbdInteractiveAuthentication yes`, `AuthenticationMethods publickey,keyboard-interactive:pam`, a per-user secret on the host and a correct clock; a mistake in the PAM stack can refuse every login, including the console's. A security key is the stronger second factor and changes one sshd keyword.

### Ubuntu 26.04

Same family, same adapters: the OS table, the codename for vendor sources (Docker, Caddy, Tailscale; cloudflared uses `any`), the VM image and the container image. Each vendor repository must publish the codename before its module claims 26.04; until then the module is not applicable there, with a note. `docs/testing.md` and the platform table gain the row. Supported releases then are Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04.

### v1.0: what stable means

1.0.0 is a promise about what an upgrade within 1.x will not break. `docs/stability.md` states it; in short:

| Surface | Stable in 1.x | Allowed in a minor release |
|---|---|---|
| Profile format | `schema = 1`: every key and value valid in 1.0 parses the same in every 1.x | New optional params and modules, new values for an enum param |
| Built-in profiles | Never gain a module that needs the timer; never drop a module | A safer value for an existing setting, in the release notes |
| CLI | Commands, flags and their meaning; a plain `apply` still selects only `kernel.sysctl` and `updates.auto` | New commands and flags |
| Exit codes | 0 success, 1 audit failed / rolled back / drift, 2 error, 3 rollback incomplete, 4 pending, 130 interrupted | New codes only for new commands |
| JSON output (`audit`, `plan`, `history`, `drift`, `modules`) | Existing fields keep name and type | New fields; consumers must ignore unknown ones |
| `detect --json` | Not stable (facts grow and change shape) | Anything, in the release notes |
| Control IDs | An ID keeps its meaning; a retired ID is never reused | New controls; a severity change, in the release notes |
| Journal | A 1.x binary reads and rolls back every transaction written by 0.7.0 or later | New record kinds; an older binary refuses them by name instead of guessing |
| Files on the host | Paths under `/etc/vps-ready`, `/var/lib/vps-ready` and the drop-in names | New files |

**Changing the profile format later.** A breaking change means `schema = 2`. A 2.x binary keeps reading `schema = 1` files, and `vps-ready profile migrate` prints the new form; nothing rewrites a user's file in place. No migration tool is built in M7, since there is no schema 2.

**Deprecation.** A flag, param or command to be removed warns for at least one minor release, with the replacement, before a major release removes it.

**MSRV.** It matters only to `cargo install` and `sshd-config` users; release binaries are static. Policy: raised only in a minor release, to a Rust stable at least six months old, and named in the release notes. The CI check stays.

**Distro support.** A release leaves the supported list in a minor release after its standard support ends, with one release of notice. Ubuntu 22.04's standard support ends in 2027, so 1.x drops it in a minor release then.

**Journal format.** The `begin` record already carries the writer's version. 1.0 adds `format: 1`, and a binary that meets a higher format refuses that transaction with "written by vps-ready X; roll it back with that version or newer", instead of failing on an unknown record kind.

**Before tagging 1.0.0:**
- Every piece above shipped in a 0.x release, and at least two weeks passed on `1.0.0-rc.1` with no breaking change.
- A review of every module param, flag and control title, since 1.0 freezes their names; renames happen in 0.9.x.
- Journal fixtures from 0.7.0 onward read and roll back in a layer 1 test.
- All VM cycles pass on all five releases, and the manual release gates (Tailscale, the tunnel) pass.
- The `sshd-config` fuzz targets the architecture plans exist and run in CI.
- `docs/stability.md` exists and the site links it from the install page.

Not gates: SLSA L3, new distro families, a paranoid profile.

### Facts

- `cloudflared --version` when installed, and whether a cloudflared unit other than ours exists.
- The SSH session's login method: the `Accepted publickey` line for the session's sshd process, from the journal, parsed for the key type.
- `sshd -T -C user=<u>,host=<h>,addr=<a>` per sudo user, for `SSH-010` and the `Match` check.

### Resources and reloads

No new resource kinds. `net.tunnel` is a `File` (unit, origin), `apt_source`, `Package` and `Service`; `config.toml` is a `File`. `Reload::DaemonReload` before the unit's `Service` if the engine does not already order it. A v0.6 binary reads v0.7 journals, since nothing new is recorded.

### Changes to earlier docs

- `README.md`: the platforms table (RHEL and Alpine "on demand", not "v0.7"); the roadmap line (M7 is the tunnel, depth and v1.0); `audit` formats; the modules table gains `net.tunnel`.
- `architecture.md`: `drift` and `config.toml` as built, `state.json` dropped; `src/report` formats; `schemars` as a dependency; the registry order; OpenRC and firewalld no longer "M7".
- `decisions.md`: D9 (distro order) becomes "on demand, Rocky and Alma first"; D19's "CrowdSec later" becomes "if asked for"; new decisions for remotely-managed tunnels only and for the 1.x stability promise.
- `scope.md`: backups move to non-goals, with the pairing note below; the wedge's "backups" removed.
- `security-baseline.md`: the `ops.backup` row marked out of scope; FIDO2 marked as built, TOTP as deferred; the order's step 7 gains the tunnel.
- `m6-plan.md`: the tunnel section points here.
- `testing.md`, `release.md`: the new cycles and the manual tunnel gate.

**Backups, out of scope.** vps-ready hardens and then gets out of the way; backups need storage, credentials and a restore story that belong to a backup tool. The docs gain a short "Pairing with a backup tool" page: back up the app's data and `/etc/vps-ready/config.toml`, and rebuild the host from the profile (`export cloud-init`) rather than restoring `/etc`.

### Not in M7

| Idea | M7 | When |
|---|---|---|
| Rocky and Alma, Fedora, Alpine (with dnf, apk, firewalld, OpenRC adapters, `.rpm`, `.apk`) | Debian and Ubuntu | On demand; Rocky and Alma first if asked |
| Tailscale Funnel as a tunnel provider | Cloudflare only | If asked for; `provider` is ready for it |
| Locally-managed tunnels, cloudflared config files | Remotely managed, token only | Not planned (account-wide `cert.pem`) |
| Caddy DNS challenge behind the tunnel (end-to-end TLS) | HTTP on loopback | If asked for; needs a Cloudflare API token, a second secret |
| Some sites behind the tunnel, others public | One mode per host | If asked for |
| SSH through the tunnel (`cloudflared access`) | Never | Not planned: SSH goes through the VPN |
| TOTP | Security keys | Not planned unless asked for; see above |
| auditd | | 1.x, opt-in only, never in a built-in profile |
| CrowdSec | fail2ban's `sshd` jail | If asked for: it overlaps the jail and adds a third-party service with a shared blocklist |
| Backups | Documented pairing | Out of scope |
| A `paranoid` profile | `private` plus `security_keys` | After 1.0, if the opt-in pieces add up to one |
| `drift --fix`, a drift timer, notifications | `drift` and the printed `apply` | If asked for |
| Security keys in the wizard | Profile only | If asked for |
| SSH certificates (a user CA) | Keys | If asked for |
| Nightly real-cloud runs | Owner decision (20) | |
| `ratatui` plan view | Plain text | As in M4 |

## Testing

**Layer 1:**
- `net.tunnel`: the apt source (suite `any`) and embedded key fingerprint; the origin file; the unit (`insta`), with `--edge-ip-version auto` on an IPv6-only fixture; the token path appears only in `LoadCredential=` and the token never in any output (a test writes a marker token and greps every byte the engine wrote); key-file checks (group or other bits, symlink, not root's) refused; no `token_file` plans the install and the note; an old `cloudflared` refused; a hand-made `cloudflared.service` not applicable; export refuses `token_file`; rollback removes the unit and keeps the package.
- `deploy.proxy` `behind_tunnel`: the Caddyfile (`insta`); no DNS or firewall note; the "nothing forwards" note; switching modes.
- `config.toml`: resolved and merged per module; written in the transaction and restored by rollback; no secret content.
- `drift`: none after apply; a hand edit, a runtime sysctl, a stopped service, each reported with module and transaction; exit codes; `--json`; no `config.toml`.
- JSON Schema: every built-in profile and every test profile validates; a typo fails; the schema snapshot changes only with a params change.
- SARIF: validates against the SARIF 2.1.0 schema; rules for every control; fingerprints stable across runs. JUnit: parses; counts match the text report.
- `security_keys`: the drop-in with and without the `Match` block (`insta`); refusals 1 to 5, each from a fixture (journal lines for `ED25519`, `ED25519-SK`, `ECDSA-SK`, rotated away); `pin`; `SSH-010` skipped without `sk-` keys.
- Journal `format`: a higher format refused by name; fixtures from each 0.x since 0.7.0 roll back.

**Layer 2 (containers):** `net.tunnel` installs from Cloudflare's real repository on all images; `cloudflared --version` is at least 2025.4.0; the unit starts with a dummy token file, `ready` fails, and verify reports it; `unattended-upgrade --dry-run` lists the origin; rollback removes the source. Caddy behind the tunnel answers `curl -H 'Host: app.example.com' http://127.0.0.1/` and nothing listens on a public address.

**Layer 3 (VMs):** a `security-keys` cycle on all five releases. No hardware key is needed: the runner logs in with an `sk-` key backed by a software authenticator (OpenSSH's test middleware, `SSH_SK_PROVIDER`), so the cycle checks:
1. Refusal 2 from a session with a plain key; the apply from a session with the `sk-` key.
2. During the window, a new plain-key login as admin is refused; a confirm from a new `sk-` login succeeds; the deploy account still logs in with its plain key.
3. Not confirmed: at the deadline, plain keys work again.
4. `sshd -T -C` for admin and deploy, after a reboot too.

If the software authenticator proves unworkable in CI, step 2 runs in the manual release gate with a real key instead.

**Release gate (manual):** a tunnel needs a Cloudflare account and a domain. Before tagging a release with `net.tunnel`, the maintainer creates a tunnel, applies `private` with `net.tunnel` and `deploy.proxy` on one Debian 13 and one Ubuntu 24.04 VM, loads the site through Cloudflare, checks the app sees the visitor's address and `Host`, checks from outside that no TCP port answers (with Tailscale for SSH), reboots, and records it in the release PR.

## PR sequence

1. **`docs: plan M7`** (this document).

Wave 1, v0.7.0:

2. **`feat(modules): net.tunnel`**: the vendor source and key with its weekly check, the origin file, the unit, verify through `ready`, the layer 2 cycle. *Parallel with 3.*
3. **`feat(modules): deploy.proxy behind_tunnel`**. *Parallel.*
4. **`feat(cli): the tunnel in the wizard and the private profile`** (needs 2 and 3).

Wave 2, v0.8.0:

5. **`feat(audit): SARIF and JUnit output`**. *Parallel with 6 and 8.*
6. **`feat(config): record the applied profile in config.toml`**. *Parallel.*
7. **`feat(cli): drift`** (needs 6).
8. **`feat(config): JSON Schema for profiles`**. *Parallel.*

Wave 3, v0.9.0:

9. **`feat(modules): security-key logins in ssh.server`**: starts with the `Match` VM check; then the param, refusals, `SSH-010`, the VM cycle. *Parallel with 10.*
10. **`feat(platform): Ubuntu 26.04`**. *Parallel.*

Wave 4, v1.0.0:

11. **`feat(engine): journal format field`** and the compatibility fixtures. *Parallel with 12.*
12. **`docs: stability policy`**: `docs/stability.md`, the name review's renames (or a 0.9.x PR of its own if code changes).
13. **`docs(site): tunnel, drift, security keys, stability`**: the guides and the doc changes above. Each wave updates the pages it touches; this PR finishes them.
14. **`chore: release v1.0.0-rc.1`**, then **`chore: release v1.0.0`** after two weeks.

Waves: {2, 3} → 4 → {5, 6, 8} → 7 → {9, 10} → {11, 12} → 13 → 14. Each wave is a release; a wave that slips does not hold the next one, except wave 4, which needs all of them.

## Fact check

Checked against upstream docs while writing this plan; items marked VM are checked in the PR that needs them.

| Claim | Source |
|---|---|
| Debian and Ubuntu install: key `cloudflare-main.gpg`, repository `https://pkg.cloudflare.com/cloudflared`, suite `any`, component `main`; per-codename suites also exist | Cloudflare package repository page (pkg.cloudflare.com) |
| `Origin: cloudflared`, `Codename: any`; amd64 and arm64; version 2026.11.1 on 2026-11-19; the key is RSA 4096, created 2025-10-23 | The repository's `Release` and `Packages` files and the key, downloaded |
| `--token-file` / `TUNNEL_TOKEN_FILE` need 2025.4.0 and work for remotely-managed tunnels only; `cloudflared service install` puts the token in `ExecStart`, visible in `systemctl status`; `--edge-ip-version` defaults to 4; `--protocol auto` prefers QUIC and falls back to HTTP/2; the updater does nothing for package-manager installs | Cloudflare docs, tunnel run parameters |
| Remotely managed: created in the dashboard, configuration at Cloudflare; locally managed: created with `cloudflared tunnel create`, configuration in a local directory | Cloudflare docs, tunnel useful terms |
| Outbound port 7844 TCP and UDP to the edge; no inbound port | Cloudflare docs, tunnel with firewall |
| `httpHostHeader` defaults to empty; `originServerName`; `noTLSVerify` | Cloudflare docs, origin parameters. That an empty value passes the visitor's `Host` through: layer 2 and the release gate |
| Metrics server on loopback (20241 to 20245 by default); `/ready` returns 200 with at least one registered connection, 503 otherwise; `cloudflared tunnel ready` | Cloudflare docs, tunnel metrics; cloudflared source, `metrics/readiness.go` |
| `Type=notify` and the sandboxing lines work for the connector | VM (layer 2) |
| `LoadCredential=` added in systemd 247, readable by the unit's user including a `DynamicUser`; `${CREDENTIALS_DIRECTORY}` in `ExecStart` | systemd.exec(5) |
| systemd versions: Debian 12 252, Debian 13 257, Ubuntu 22.04 249, Ubuntu 24.04 255 | Debian and Ubuntu package indexes |
| `http://` site addresses turn off automatic HTTPS for the site; `default_bind`; `trusted_proxies`; `client_ip_headers`; `auto_https` values | Caddy docs, Automatic HTTPS; Caddy docs, global options |
| `ecdsa-sk` and `ed25519-sk` key types and the touch requirement since OpenSSH 8.2; `verify-required` since 8.4 | OpenSSH 8.2 and 8.4 release notes |
| OpenSSH versions: Debian 12 9.2, Debian 13 10.0, Ubuntu 22.04 8.9, Ubuntu 24.04 9.6 | Debian and Ubuntu package indexes |
| `Match` in an included file ends at the end of that file | sshd_config(5); OpenSSH regression test `servcfginclude.sh`; VM (`sshd -T -C`) |
| The `Accepted publickey ... ED25519-SK` line and its `_PID` on each release | VM (fixtures captured in PR 9) |
| SARIF 2.1.0 only; a result needs a location; `security-severity` bands; `partialFingerprints`; per-run limits | GitHub docs, SARIF support for code scanning |

## Decisions for the owner

1. **Releases: v0.7.0 the tunnel, v0.8.0 `drift`, `config.toml`, SARIF/JUnit and the JSON Schema, v0.9.0 security keys and Ubuntu 26.04, then v1.0.0.** Recommended: the owner's split, with the schema moved next to `config.toml` and auditd out. Alternative: auditd in v0.9.0.
2. **Cloudflare Tunnel, remotely-managed tunnels only.** Recommended: the host needs only a token for one tunnel, not the account-wide `cert.pem`. Alternative: also support locally-managed tunnels with a config file.
3. **vps-ready's own unit with `LoadCredential=`, `DynamicUser=yes` and `--token-file`,** never `cloudflared service install`. Recommended: the token stays out of argv and the unit file, and the connector never runs as root. Alternative: Cloudflare's unit with the token in `ExecStart`.
4. **The token only through a root-only file the user creates (or the wizard's hidden prompt); without it, install only with a note; `export` refuses `token_file`.** Recommended: the same rules as Tailscale's auth key.
5. **cloudflared updates through unattended-upgrades** (`origin=cloudflared,codename=any`). Recommended: the connector faces the internet and must get updates. Alternative: leave updates to the user.
6. **Verify with `cloudflared tunnel ready` on a fixed loopback metrics port; a failed verify rolls back the apply.** Recommended: a bad token is caught at apply time. Alternative: check only that the unit is active.
7. **`deploy.proxy` `behind_tunnel`: plain HTTP on loopback, TLS at the edge, visitor addresses from `Cf-Connecting-Ip` with loopback as the only trusted proxy.** Recommended: no second secret and no port to open. Alternatives: the DNS challenge with a Cloudflare API token for TLS to the origin; or no Caddy, the tunnel pointing straight at the app (still possible without `deploy.proxy`).
8. **No safety timer for `net.tunnel`** and no new built-in profile; the wizard offers it only with `private`. Recommended: it cannot touch SSH.
9. **`config.toml` resolved (no `extends`), merged per module, written in the same transaction.** Recommended: drift reports only what an apply did, and rollback keeps it in step. Alternative: a copy of the profile as written.
10. **`drift` is a read-only plan against `config.toml`, with no `state.json`;** exit 1 on drift; no `--fix`. Recommended: one comparison path, the plan's, already tested. Alternative: a hash store written at apply.
11. **The JSON Schema in M7, generated with `schemars`.** Recommended: it is the published contract of `schema = 1` that 1.0 freezes. Alternative: defer it past 1.0 and keep the dependency out.
12. **`audit --format text|json|sarif|junit`, with `--json` kept.** Recommended over a separate flag per format.
13. **SARIF with a logical location (the host) and a synthetic `<host>/<control>` physical location,** so GitHub code scanning shows the results. Recommended. Alternative: logical locations only, valid SARIF that code scanning does not display.
14. **`security_keys = "required"` restricts `PubkeyAcceptedAlgorithms` to the `sk-` types, refused unless the admin has an `sk-` key and the applying session logged in with one; the timer's new-login confirm is the proof; `deploy.user` exempt through a `Match` block; `pin` opt-in.** Recommended as a set; the `Match` VM check decides whether the exemption ships or `security_keys` refuses alongside `deploy.user`.
15. **Defer TOTP.** Recommended: a PAM mistake can refuse every login, including the console's, and security keys cover the need. Alternative: TOTP as an opt-in in v0.9.0.
16. **auditd after 1.0, opt-in only, never in a built-in profile.** Recommended: an opt-in module is additive in 1.x, so it need not land before the freeze, and its value on a single VPS without log shipping is small. Alternative: in v0.9.0.
17. **CrowdSec deferred; backups out of scope, with a pairing page.** Recommended: CrowdSec overlaps the fail2ban jail and adds a third-party service; backups need storage and credentials vps-ready should not hold.
18. **No `paranoid` profile in M7.** Recommended: its pieces arrive as opt-in params; a profile can follow once they add up to one.
19. **Ubuntu 26.04 in M7.** Recommended: 1.0 should support the current LTS, and it is the same family. Alternative: after 1.0, in a minor release.
20. **Nightly real-cloud runs: owner decision.** They cost money and need a provider API token in a protected environment. Recommended: a `workflow_dispatch` run before each release (export, boot, check from outside that only the expected ports answer, destroy), not nightly. Alternatives: nightly as `testing.md` describes; or none, keeping the manual gates.
21. **The 1.x promise as in [v1.0](#v10-what-stable-means): `schema = 1` additive only, CLI and exit codes stable, JSON additive, `detect --json` excluded, journal `format: 1`, deprecation with one minor of warning, MSRV raised only in a minor to a Rust at least six months old.** Recommended as a set.
22. **1.0.0 through `1.0.0-rc.1` with two weeks and no breaking change,** after a review of every name. Recommended: names freeze at 1.0, so they are checked once on purpose.
