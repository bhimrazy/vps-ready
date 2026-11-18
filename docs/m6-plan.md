# M6 plan: private access (v0.6.0)

> **Status: proposed.** Nothing below is built yet. The open questions are at the end, each with a recommendation.

M6 lets an admin reach SSH through a private network and then close it to the internet. It has three parts: `net.wireguard`, a WireGuard server on the host for admin access to the host itself; `net.tailscale`, which installs Tailscale and joins a tailnet; and `ssh_via`, a `firewall.inbound` parameter that accepts SSH only on one named interface (`wg0`, `tailscale0`, or any interface the admin set up, such as NetBird's). It also brings `export cloud-init`, moved here by the [M5 plan](m5-plan.md#direction-for-v060-private-access): a server hardened at first boot, before anyone logs in, is the other half of "never exposed". With a VPN for SSH and, later, a tunnel for the web, a server can end with no public TCP port at all; this plan says what that looks like, and why the web tunnel waits.

`ssh_via` is the highest lockout risk in the project: after it, a broken VPN means no SSH at all. Most of this plan is about that step. The two VPN modules are ordinary modules that do not touch sshd or the SSH rule; the close step stays behind the safety timer with a stricter confirm.

The engine, the journal and the safety timer stay as they are, apart from two new resource kinds, two new reloads, one new field in the `pending-confirm` record and one new confirm refusal.

Debian 12/13 and Ubuntu 22.04/24.04 with systemd, as in M5. Earlier docs use "M6" for RHEL, Alpine, `drift` and the paranoid profile; with this plan those become M7.

## Decisions

### Scope

| Piece | Changes | Fixes | Safety timer |
|---|---|---|---|
| `net.wireguard` | installs `wireguard-tools`; `/etc/wireguard` (0700), a generated `/etc/wireguard/wg0.key` (0600), `/etc/wireguard/wg0.conf`; enables and starts `wg-quick@wg0` | `NET-007` (new) | no (yes when the firewall changes in the same apply) |
| `net.tailscale` | Tailscale's apt source and key, `tailscale`; enables and starts `tailscaled`; joins with an auth key from a file | none | no |
| `firewall.inbound` `ssh_via` | the same ruleset, with the SSH rule limited to one interface | `SSH-009` (new, reported only) | yes, with the stricter confirm below |
| `export cloud-init` (priority) | nothing where it runs; prints `#cloud-config` that hardens a new server at first boot | every module the profile has | off at first boot, through `apply --deadman=off` (below) |
| `FW-003` (audit) | nothing; lists the ports open to the internet | reported only | |

`--deadman=selftest` is cut, and a web tunnel module (`net.tunnel`) is deferred (see [Hardened before exposed](#hardened-before-exposed-export-cloud-init) and [Web through a tunnel](#web-through-a-tunnel-nettunnel-deferred)).

The registry order becomes `user.admin`, `ssh.server`, `net.wireguard`, `net.tailscale`, `firewall.inbound`, `ssh.bruteforce`, `kernel.sysctl`, `updates.auto`, then the deploy modules. The VPN modules come before the firewall so that `firewall.inbound` sees their planned resources, as it already does for `deploy.docker`.

**The flow is two applies.** The first sets up the VPN (and opens its port). The admin then connects through it and runs the second apply, with `ssh_via`, from that private session. The plan refuses `ssh_via` from a session that does not come through the named interface, so public SSH is never closed before the private path has carried a real login. The wizard follows the same two steps.

### `net.wireguard`

A WireGuard interface for admin access to this host only. Not a routing VPN: no forwarding, no `0.0.0.0/0`, no exit node. Peers reach the host's tunnel address and nothing else, so the module needs no `ip_forward`, no forward rules and no NAT, and cannot interfere with Docker's forwarding.

```toml
[modules."net.wireguard"]
port = 51820                     # default
address = "10.86.12.1/24"        # optional; the default is derived per host (below)
endpoint = "203.0.113.10"        # optional; only for the printed client config
peers = [
  { name = "laptop", public_key = "<44 base64 characters>", address = "10.86.12.2" },
]
```

**Package and kernel.** WireGuard has been in the mainline kernel since 5.6, and all four releases ship newer kernels: Debian 12 has 6.1, Debian 13 has 6.12, Ubuntu 22.04 has 5.15 (6.8 with HWE) and Ubuntu 24.04 has 6.8. So only `wireguard-tools` is installed (`wg`, `wg-quick` and the `wg-quick@.service` template), with `--no-install-recommends` as for every `Package`. Not applicable when `modprobe --dry-run wireguard` fails and `/sys/module/wireguard` is missing, which is the case in LXC and OpenVZ containers and on a stripped kernel. The VM test checks the four cloud kernels (Debian's `cloud` flavor, Ubuntu's `generic` and `kvm` flavors).

**Not applicable** when `/etc/wireguard/wg0.conf` exists without the vps-ready header, or a `wg0` interface exists that our file did not create. That is a hand-made setup: vps-ready leaves it alone, and `ssh_via = "wg0"` works with it. The interface name is fixed at `wg0`; a second interface is not in M6.

**The private key** is generated on the host and never leaves it:
- A new resource, `WireguardKey { path }`, for `/etc/wireguard/wg0.key`. Apply: if the file is missing, run `wg genkey`, keep its stdout in memory only, and write it atomically, root-owned, mode 0600. If it exists (root-owned, 0600, a regular file, not a symlink, 44 base64 characters), it is kept. Its backup records only `created` and the public key (`wg pubkey` with the key on stdin).
- `wg0.conf` holds no `PrivateKey`. It loads the key with `PostUp = wg set %i private-key /etc/wireguard/%i.key`, the form `wg(8)` documents ("private-key ... must be files, because command line arguments are not considered private"). So `wg0.conf` is an ordinary `File` whose before and after copies in the journal hold nothing secret.
- The key is never in plan output, the journal, a log or an error message. The runner call that reads `wg genkey`'s stdout redacts it from errors. vps-ready never runs `wg showconf` or `wg show <if> dump`, which print the private key; it reads `wg show wg0 public-key`, `listen-port`, `peers` and `allowed-ips` only.
- **Rollback keeps a generated key** (the resource is `partial`, and the plan says so). The next apply reuses it, so client configs made in the window keep working. Removing it would mean that a timeout during the first setup forces every client to be redone. `rm /etc/wireguard/wg0.key` rotates it by hand.

**`wg0.conf`, not systemd-networkd.** Debian and Ubuntu cloud images do not all manage their network with networkd (Debian 12's images use ifupdown), `wg-quick@.service` ships with the package, and `wg0.conf` is the format every WireGuard guide and client app shows. The rendered file:

```ini
# Written by vps-ready (net.wireguard). `vps-ready rollback --last` restores
# the previous state; edits here are replaced by the next apply.
# The private key is in /etc/wireguard/wg0.key and is loaded by PostUp.
[Interface]
Address = 10.86.12.1/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/%i.key

[Peer]
# laptop
PublicKey = <public key>
AllowedIPs = 10.86.12.2/32
```

- No `MTU`: `wg-quick(8)` derives it from the endpoint or the default route when unset, which is right for a server. An optional `mtu` param exists for links that need less.
- No `PersistentKeepalive` on the server: it does not start connections, and `wg(8)` says most users do not need it. The printed client config sets it (below).
- No `SaveConfig`, which would overwrite the file from the running interface at shutdown.
- No `Table`, no `DNS`: with only `/32` peer routes, `wg-quick` adds plain routes, no policy rules, and needs no `resolvconf`.
- `Service { unit: "wg-quick@wg0.service", enabled: true, active: true }`. The unit is ordered after `network-online.target` and is wanted by `multi-user.target`.

**Reloads.** A new `Reload::WireguardReload`: check with `wg-quick strip wg0`, then `systemctl try-reload-or-restart wg-quick@wg0.service`, whose `ExecReload` runs `wg syncconf %i <(wg-quick strip %i)` "without disrupting active sessions" (`wg-quick(8)`). The stripped file has no `PrivateKey`, and `syncconf` only changes what is explicitly different, so the loaded key stays (checked in the VM test). Peers and the port change this way. `Address` and `MTU` are `wg-quick` settings that only an interface restart applies, so changing them on an active `wg0` plans `Reload::WireguardRestart` (`systemctl restart`) with a note, and is refused when the applying session comes through `wg0` ("this would cut this session; run it from public SSH or the console").

**Addresses.** IPv4 inside the tunnel only; the endpoint itself may be IPv4 or IPv6. The default subnet is a `/24` inside `10.0.0.0/8` derived from `/etc/machine-id` (two bytes of a SHA-256 over it and a fixed label), with the server at `.1`. Why this range and this rule:
- RFC 1918 rather than `100.64.0.0/10`: Tailscale uses that CGNAT range for its own addresses, and some ISPs use it on the client's side.
- `10.0.0.0/8` rather than `172.16.0.0/12` or `192.168.0.0/16`: Docker's default address pools take `172.17.0.0/16` upward and parts of `192.168.0.0/16`, and home routers use `192.168.x.0/24`.
- Derived per host rather than one fixed default: a laptop with tunnels to two servers needs two subnets that do not overlap, and the `10.0.x` and `10.8.x` subnets that tutorials and other tools use are the ones most likely to collide. Deriving from the machine ID needs no stored state, gives the same answer on every plan, and differs between servers (cloud images get a new machine ID at first boot).
- **Collision check at plan time:** the subnet must not overlap any address or route on the host (`ip -j addr`, `ip -j route show table all`) other than `wg0`'s own. A collision is refused with the overlapping route and the `address` param to pick another. There is no "try the next one": the answer stays predictable. The client's own networks cannot be checked from here; the docs say to pick `address` if the derived one collides there.
- Peers get `.2`, `.3` and so on in list order unless they set `address`. A change in a peer's address compared with the current `wg0.conf` is a plan note ("laptop moves from 10.86.12.2 to 10.86.12.3; its client config must change"). The wizard always writes `address`.
- IPv6 ULA inside the tunnel is not offered: admin access needs one address family, and an IPv4 tunnel runs fine over an IPv6 endpoint.

**Peers** are public keys only. `check_params` checks: a `name` of lowercase letters, digits and `-`, unique; a `public_key` that decodes from base64 to 32 bytes, unique, and not the server's own; an `address` inside the subnet, not `.0`, `.1` or the broadcast address, unique. An empty `peers` list is allowed (the interface comes up, nothing can connect) with a note. Removing the peer that the applying session comes through is refused. Preshared keys are not in M6: they are a second secret per peer to generate and hand over.

**The firewall port.** `firewall.inbound` accepts UDP on the listen port of every WireGuard interface that is up (`wg show all listen-port`, which prints no keys) and of a `wg0.conf` that `net.wireguard` plans in the same apply. This is the same rule as "never cut the current SSH port": a firewall apply must not cut the VPN that SSH may depend on. WireGuard does not answer unauthenticated packets, so the open port reveals nothing. The plan says which ports and why. If `firewall.inbound` does not apply (ufw is active), the plan says to open the port there.

**The client config** is printed after apply and by `sudo vps-ready wireguard-config [PEER]` at any time:

```ini
[Interface]
PrivateKey = <the private key of laptop, which stays on that device>
Address = 10.86.12.2/32

[Peer]
PublicKey = <this server's public key>
Endpoint = 203.0.113.10:51820
AllowedIPs = 10.86.12.1/32
PersistentKeepalive = 25
```

- `Endpoint` is `endpoint` if set, else the applying session's server address if it is public, else a public address on the default-route interface, else `<this server's public address>` with a note. No network call is made to find a public address (as in M3). On NATed clouds the host only has its private address, so the placeholder and the note are the normal case there.
- `AllowedIPs` is the server's `/32`: the client routes only the tunnel address through it.
- `PersistentKeepalive = 25` on the client keeps its NAT mapping while an SSH session is idle.
- **No QR code.** A QR code is useful when it carries the whole config, private key included, for a phone to scan. Here the private key never leaves the client, so a QR of this text would save typing a few lines and would add the `qrcode` crate. Generating client keys on the server (and printing them once, with a QR) is listed under Not in M6.

**Idempotency and drift.** The plan compares `wg0.conf` and the key file as files, so a second apply plans nothing. `verify` reads back `wg show wg0 public-key`, `listen-port` and the peers with their allowed IPs, and fails if they differ from the file. A running interface changed with `wg set` while the file did not change is reported by the next apply's `verify`, and fixed with `systemctl reload wg-quick@wg0`; vps-ready does not track runtime drift on its own (that is `drift`, M7).

### `net.tailscale`

```toml
[modules."net.tailscale"]
auth_key_file = "/root/tailscale-auth-key"   # optional
login_server = "https://headscale.example.com" # optional, for Headscale
hostname = "web-1"                             # optional
```

**Install.** Tailscale's repository through the M5 `apt_source` helper: `https://pkgs.tailscale.com/stable/debian` or `/ubuntu`, the host's codename as the suite (`bookworm`, `trixie`, `jammy`, `noble` are all published), component `main`. Tailscale publishes one key for all four codenames: the armored `<codename>.gpg` files are byte-identical, and so are the `.noarmor.gpg` ones. The armored key is embedded at `keys/tailscale.asc` with its fingerprint in the source, and the weekly key check gains it. Then `Package tailscale` and `Service tailscaled` (enabled, active).

**Joining.** A new resource, `TailscaleUp { auth_key_file, login_server, hostname }`, planned only when `tailscale status --json` shows a `BackendState` other than `Running`:
- Apply: `tailscale up --auth-key=file:<path> --accept-dns=false [--login-server <url>] [--hostname <name>] --timeout=60s`. `tailscale up` reads the key itself when the value starts with `file:` (Tailscale's `tailscale up` docs), so the key is never in vps-ready's memory, argv, `ps`, the journal, the plan or shell history. The profile holds only the path.
- The key file must be a regular file owned by root with no group or other permissions, and not a symlink; otherwise the plan refuses. vps-ready does not read or delete it; the plan says to delete it after the join (a one-off key is revoked once used anyway).
- **No key file and not logged in:** the module installs and starts `tailscaled`, plans no join, and says "log in with `sudo tailscale up --accept-dns=false`, then apply again". vps-ready does not drive the browser login: it would need the URL streamed from a running command, which the engine does not do.
- **Already logged in:** nothing to do. Flags of a joined node are not changed (`tailscale up` refuses to change settings without `--reset`, and vps-ready does not reset them).
- `--accept-dns=false`: the default accepts the tailnet's DNS settings and rewrites the host's resolver, which a server does not need for admin access and which rollback could not cleanly restore. `--accept-routes` stays at its Linux default (off). No `--advertise-exit-node` or `--advertise-routes`.
- **No `--ssh`.** Tailscale SSH replaces sshd's authentication with the tailnet's access policy, so `ssh.server`'s settings and `user.admin`'s keys no longer decide who logs in, and its sessions have no sshd process, so `confirm` could not tell a new login from an old one. The point of this module is a private path to the same sshd.
- **Key types.** The docs recommend a one-off or pre-approved key, ideally tagged: tagged devices have key expiry disabled by default, and an ephemeral node is removed from the tailnet once it goes idle (Tailscale's auth key docs), which would make the server disappear after an outage. vps-ready cannot see the key's type; the docs say so.
- Verify: `BackendState` is `Running` and `Self.TailscaleIPs` is not empty.

**Rollback** runs `tailscale down` if the node was not `Running` before (it stays logged in), then the `Service` restore stops and disables `tailscaled` if it was off before. No `tailscale logout`: logging out expires the node key, so applying again would need a new auth key, and a one-off key is already spent. The package, the apt source (removed like the others) and `/var/lib/tailscale` are partial: the package stays, as for every `Package`, and the state directory stays. The plan says so, with `tailscale logout` as the by-hand step.

**Other notes in the plan:**
- tailscaled adds its own netfilter rules (`ts-input` and friends). They are base chains in other tables and coexist with `inet vps_ready`, as fail2ban's do; a packet must pass every base chain.
- No inbound port is needed: Tailscale's firewall docs say "you don't need to open any firewall ports for Tailscale" in most cases, and our `established,related` rule covers the replies.
- `updates.auto` does not include Tailscale's origin, so Tailscale is not updated automatically; `tailscale set --auto-update` is Tailscale's own way, and vps-ready does not turn it on.

### SSH only through a private interface: `ssh_via`

```toml
[modules."firewall.inbound"]
allow = ["80/tcp", "443/tcp"]
ssh_via = "wg0"            # or "tailscale0", "nb0", ...
```

**What changes in the ruleset.** One line: the SSH rule becomes `iifname "wg0" tcp dport { 22 } accept`. Everything else stays: loopback, ICMP, DHCP, `established,related`, Docker's bridges, `allow`. `iifname` matches the name at packet time, so the table loads before `wg0` exists (at boot) and keeps matching after the interface is recreated; `iif` would not, since `nftables` resolves it to an index when the rule loads. The `inet` table covers IPv4 and IPv6, so public SSH closes on both.

**sshd is not changed.** No `ListenAddress` on the tunnel address: sshd would fail to bind at boot when it starts before the VPN, which is a lockout of its own, and the firewall already closes the public path. Port 22 stays (D6).

**SSH ports in `allow`** (the built-in `minimal` and `web` list `22/tcp`) are left out of the public set when `ssh_via` is set, with a note ("22/tcp in `allow` is left out: `ssh_via` limits SSH to wg0"). Refusing instead would make every profile that `extends` a built-in one restate `allow`.

**Refused at plan time** (all read-only):
1. The interface does not exist, is down, or has no address.
2. No SSH session (the console, cloud-init): "`ssh_via` needs an SSH login through wg0".
3. **The applying session does not come through the interface:** its server address (from the process tree, as `confirm` reads it) is not an address of `ssh_via`. The message says to connect through the VPN first and gives the command (`ssh admin@10.86.12.1 sudo vps-ready apply ...`). This is the "proven before 22 closes" rule: a login over the VPN already works when the apply starts, and the "never cut the current SSH port" invariant holds because that session's path is the one kept open.
4. The VPN would not come back after a reboot: for an interface with `/etc/wireguard/<if>.conf`, `wg-quick@<if>` is not enabled; for `tailscale0`, `tailscaled` is not enabled. For other interfaces vps-ready cannot tell, and says so in a note.
5. `tailscale0` while this node's key expires: `tailscale status --json` shows `Self.KeyExpiry`. Tailscale's default is 180 days, and when it expires "connections to/from the given endpoint will stop working" (Tailscale's key expiry docs), which with `ssh_via` is a lockout on a date nobody remembers. The message says to disable key expiry for this machine in the admin console (or join with a tagged key) and apply again.
6. `lo`, `docker0`, `br-*`, or an interface that is the host's default route: not a private path.
7. `--deadman=off`.

**Notes, not refusals:**
- **Console recovery.** The plan's last note before the prompt: "If wg0 stops working, SSH is closed. Your provider's web console logs in with a password, so set one for a sudo user (`sudo passwd admin`) if you have not; without it, recovery needs the provider's rescue mode. From the console: `sudo systemctl stop vps-ready-firewall` opens everything until the next boot; `sudo vps-ready rollback --txn <id>` undoes this change." It checks `/etc/shadow` and says which case applies. A refusal here would push every user to set a password; sshd still refuses passwords (`SSH-002`), so a console-only password is reasonable, but it is the admin's choice.
- Which unit brings the interface up at boot, and that SSH is unreachable from boot until it is up.

**The safety timer and the confirm.** `ssh_via` arms the timer, as every `firewall.inbound` change does, and the confirm is stricter:
- `state pending-confirm` gains `ssh_via: "wg0"` (absent when not set, so older journals read as before).
- `confirm` then also requires the new login's server address to be an address that `ssh_via` has at confirm time. Otherwise a new refusal, `Refusal::NotVia { interface, server }`: "this SSH login came in on 203.0.113.10, not through wg0; log in through wg0: `ssh -t -o ControlPath=none admin@10.86.12.1 sudo vps-ready confirm`". The other rules (new session, started after `live_since`, a port sshd listens on, the plan's admin, not loopback) stay.
- The printed `ssh` line uses the applying session's server address, which rule 3 makes the VPN address.
- The confirm proves that a new login through the VPN works under the new ruleset. It does not prove that public SSH is closed; `verify` does that, by reading the table back: the SSH ports are accepted only with `iifname` equal to `ssh_via`.

**What can still go wrong, and what covers it:**

| Case | Covered by |
|---|---|
| The VPN path does not work for new logins | No confirm, so the timer rolls back and public SSH reopens |
| The session drops during apply | The first-arm timer rolls back at its deadline |
| Reboot during the window | The boot hook rolls back before sshd starts (M3) |
| Reboot after the confirm | Our firewall loads at `network-pre.target` with the `iifname` rule; SSH works once `wg-quick@wg0` (after `network-online.target`) or `tailscaled` is up; refusal 4 checks they are enabled |
| The VPN breaks later (key expiry, a bad edit, a peer removed) | Refusal 5 for Tailscale expiry; otherwise the console note. vps-ready cannot help after the confirm |
| A later `apply` without `ssh_via` | Reopens public SSH, behind the timer, as any firewall change |

### Hardened before exposed: `export cloud-init`

A priority of this release, and in the first wave. Pasted into the provider's user-data when the server is created, it hardens the server at first boot, before anyone logs in, and the same profile creates the next fifty.

```
vps-ready export cloud-init --profile vps-ready.toml --checksums checksums.txt [--base-url URL]
```

**What it prints**, for the version of the running binary:

```yaml
#cloud-config
# vps-ready 0.6.0 (export cloud-init): hardens this server at first boot.
write_files:
  - path: /etc/vps-ready/profile.toml
    permissions: "0600"
    content: |
      schema = 1
      extends = "web"
      [modules."user.admin"]
      name = "admin"
      authorized_keys = ["ssh-ed25519 AAAAC3Nza... me@laptop"]
runcmd:
  - - sh
    - -c
    - |
      set -eu
      case "$(uname -m)" in
        x86_64) t=x86_64-unknown-linux-musl; sum=<sha256 from checksums.txt> ;;
        aarch64) t=aarch64-unknown-linux-musl; sum=<sha256 from checksums.txt> ;;
        *) echo "vps-ready: unsupported architecture" >&2; exit 1 ;;
      esac
      f=/root/vps-ready-0.6.0-$t.tar.gz
      curl -fsSL -o "$f" "https://github.com/bhimrazy/vps-ready/releases/download/v0.6.0/vps-ready-0.6.0-$t.tar.gz"
      echo "$sum  $f" | sha256sum -c -
      tar -xzf "$f" -C /root
      install -m 0755 "/root/vps-ready-0.6.0-$t/vps-ready" /usr/local/bin/vps-ready
      vps-ready apply --profile /etc/vps-ready/profile.toml --yes --deadman=off
```

- **The hashes come from `checksums.txt`,** which the user downloads from the release and verifies first (`cosign verify-blob` or `gh attestation verify`, as the install page shows). The binary cannot know its own release hashes, and `export` makes no network call. The tarball's SHA-256 is checked on the server before anything runs, so `--base-url` (a mirror, or the VM test's local server) cannot change what runs.
- **Small:** one profile and a dozen lines, far below AWS's 16 KB user-data limit. Plain `#cloud-config` with `write_files` and `runcmd`, which every provider's cloud-init supports. It does not touch cloud-init's own users or keys.
- **When it runs:** `runcmd` runs in cloud-init's final stage, after the network and sshd are up, so the image's own sshd settings apply for the first minute or so. Cloud images ship with password logins off; a provider firewall kept closed until first boot finishes covers that minute fully, and the docs say so.
- **Failures are visible:** `set -e` makes `runcmd` fail on a bad hash, a failed download or a failed apply (which rolls back as any apply does), so `cloud-init status` shows `error` and `/var/log/cloud-init-output.log` has the reason. `vps-ready history` shows the transaction.
- **Refused by `export`:**
  - `user.admin` without `authorized_keys`: at first boot there is no SSH session to copy keys from, and root's keys on cloud images carry a `command=` restriction that `user.admin` skips, so the apply would refuse anyway. The profile must name the keys.
  - `ssh_via`: no session can come through the VPN at first boot (refusal 3 above).
  - `net.tailscale` with `auth_key_file`: user-data is readable through the metadata service by any process on the host, so it must not carry a secret or point to one some other step would have to place. Joining Tailscale from user-data is a pattern Tailscale documents; users who accept that exposure add their own `tailscale up` line.
  - `net.wireguard` is exported: its peers are public keys, and the server key is generated on the host. `sudo vps-ready wireguard-config` prints the client config after the first login.

**The safety timer at first boot.** Nobody is logged in to confirm, so the exported command uses `--deadman=off`:
- `apply --deadman=off` applies the dead-man modules without arming the timer and records `state applied`, marked as run without the timer. Every plan-time invariant still holds: a keyed sudo admin before root and password logins are turned off, and the SSH port kept open. On a server minutes old, where rebuilding is the recovery, those invariants are enough.
- It is refused when an SSH session is detected ("you can confirm: drop `--deadman=off`") and with `ssh_via`, so it is not a way around the confirm for someone logged in.
- Rejected: arming the timer at first boot and confirming at the admin's first login. An admin who logs in an hour later finds everything rolled back, and the server unhardened with nothing saying so.
- **`--deadman=selftest` is cut.** It was to probe the new config with `ssh-keyscan localhost`, which reaches sshd over loopback (always accepted by the firewall) and proves only that sshd answers, not that anyone can log in: the reason `confirm` refuses loopback logins.

**The wizard** ends, after a successful apply, with one more line: "Same setup for a new server: `vps-ready export cloud-init --profile <file> --checksums checksums.txt`", or, when the profile has no `authorized_keys`, a line saying to add them first.

### Zero public ports

With SSH through a VPN, the last public TCP ports are 80 and 443. What this release can reach:

| Setup | Public on the host |
|---|---|
| WireGuard for SSH, no web | UDP 51820 only. WireGuard sends nothing back to a packet without a valid handshake, so a scan sees no listener |
| Tailscale for SSH, no web | No inbound port: Tailscale needs none, and the `established,related` rule covers its replies |
| Either, with a web app | 80 and 443 stay, until a tunnel exists (deferred, below) |

`firewall.inbound` then accepts: loopback, ICMP and ICMPv6, DHCP replies, `established,related`, Docker's bridges (when Docker is present), SSH on `ssh_via` only, the WireGuard listen port, and nothing from `allow`. Outbound stays open (package updates, the VPN's control plane, cloud metadata).

**No built-in `private` profile.** A built-in profile cannot name the interface or the peers, and could not work in one apply anyway (the close step needs a session through the VPN). The wizard gets there instead: with a VPN chosen and no web app, nothing is checked in its ports question, and the close step at the second run leaves no public TCP port. The saved `vps-ready.toml` (`extends = "minimal"`, `allow = []`, `ssh_via`) is the profile, and `FW-003` shows the result.

### Web through a tunnel (`net.tunnel`): deferred

Evaluated, and recommended for a later release. A tunnel would let 80 and 443 close too: an agent on the host connects out to the provider's edge, which sends web requests back through that connection.

| | Cloudflare Tunnel (`cloudflared`) | Tailscale Funnel |
|---|---|---|
| Domain | the user's own, with its DNS at Cloudflare | only `<tailnet>.ts.net` names |
| Ports | any hostname, HTTP and HTTPS | 443, 8443 and 10000 only |
| TLS | ends at Cloudflare's edge, which sees every request in plaintext | ends on the host; the relays do not decrypt |
| Limits | Cloudflare's terms for proxied traffic | "non-configurable bandwidth limits" |
| Secret | a tunnel token; `--token-file` (or `TUNNEL_TOKEN_FILE`) since cloudflared 2025.4.0, while Cloudflare's own service examples put the token in `ExecStart` | none beyond the Tailscale join; needs a `funnel` attribute in the tailnet policy, MagicDNS and HTTPS certificates |
| Install | Cloudflare's apt repository (the same `apt_source` helper) | already there with `net.tailscale` |

**Why it waits:**
- It changes `deploy.proxy`'s TLS model. Caddy gets certificates through port 80 or 443 (ACME); behind a tunnel those ports are closed, so Caddy would serve plain HTTP on loopback to `cloudflared`, or use the DNS challenge with a Cloudflare API token (a second secret). Either is a new mode for a module that is not merged yet.
- Funnel cannot serve a custom domain, so it is not a general answer for a web app, and Cloudflare Tunnel puts a third party in the TLS path of every request. That choice is a product decision, not a hardening step.
- M6 already carries the project's biggest lockout risk. SSH never goes through a web tunnel, so waiting costs nothing in safety, and the tunnel can reuse what M6 builds: the secret-file rules of `net.tailscale` (root-only file, `--token-file`, never in argv, the journal or the profile), the vendor source, and `FW-003` to show that 80 and 443 are closed.

**Direction, for when it comes:** `net.tunnel` with `provider = "cloudflare"` first (custom domains are what a web app needs), `token_file` with the same checks as `auth_key_file`, `cloudflared tunnel run --token-file` in its own unit, and `deploy.proxy` gaining `behind_tunnel = true` (HTTP on `127.0.0.1` only). Funnel as `provider = "tailscale"` for internal tools on `ts.net` names.

### Audit controls

| ID | Severity | Title | Check | Fix |
|---|---|---|---|---|
| `SSH-009` | low | SSH reachable only through a private network | new kind `ssh_private_only`: skipped when the host has no WireGuard interface and no `tailscale0`; passes when the input chains drop by default and every rule accepting an SSH port is limited to such an interface | none (the `why` names `ssh_via`; `apply --module firewall.inbound` alone would not set it) |
| `FW-003` | low | Only expected ports are open to the internet | new kind `exposed_listeners`: from the listening sockets (already in the facts) on non-loopback addresses, those the input chains let through on a non-private interface (not `lo`, not a WireGuard interface, not `tailscale0`). Fails when one of them is neither an SSH port nor 80/443 TCP or 443 UDP; the finding lists every exposed port with its process either way. Docker's published ports are left to `FW-002`. Without a default-deny chain, every listener counts as exposed | none (the finding names the ports; `firewall.inbound`'s `allow` decides) |
| `NET-007` | medium | WireGuard private keys readable only by root | new kind `wireguard_key_files`: every regular file in `/etc/wireguard` is owned by root and has no group or other permission bits; skipped without `/etc/wireguard`. Reads metadata only, never contents | `net.wireguard` (for its own files) |

`FW-003` answers "what can the internet reach": it lists every exposed port and fails only on the unexpected ones (a database, an admin panel), so a web server with 80 and 443 passes, and a zero-public-ports host shows as such. It sees the host's own firewall only; a provider firewall in front is invisible to it, as for `FW-001`. `SSH-009` is skipped rather than failed on hosts without a VPN, so v0.6.0 adds no failure (and no exit code change) to every audit. Tailscale key expiry is not a control: expiry is a security feature Tailscale recommends keeping on except for trusted servers, so it is checked only where `ssh_via` depends on it (refusal 5).

### Facts

- Interfaces with their addresses and routes, from `ip -j addr` and `ip -j route show table all` (iproute2 is on all four images): for the collision check, the endpoint guess and the `ssh_via` checks.
- WireGuard: `wg show all listen-port` and whether `/sys/module/wireguard` exists or `modprobe --dry-run wireguard` succeeds.
- Tailscale: `tailscale status --json` (`BackendState`, `Self.TailscaleIPs`, `Self.KeyExpiry`) when the command exists. Parsed into a small struct; unknown fields ignored. A layer 1 fixture per state (`NeedsLogin`, `Running`, `Stopped`).
- `detect` shows the interfaces that look like a VPN (WireGuard type, `tailscale0`) and which one the session came in on.

### Resources and reloads

| New | Backup | Unchanged when | By hand |
|---|---|---|---|
| `WireguardKey` | `{ path, created, public_key }` | the file exists with the recorded public key | none: rollback keeps it; `rm` it to rotate |
| `TailscaleUp` | `{ was_running }` | always (the node's state is Tailscale's) | `tailscale down`, or `tailscale logout` |

- Both are `partial`. Neither backup holds a secret.
- `Reload::WireguardReload` (`wg-quick strip wg0`, then `systemctl try-reload-or-restart wg-quick@wg0.service`) and `Reload::WireguardRestart` (the same check, then `systemctl try-restart`).
- `Cmd` gains stdin from a file, for `wg pubkey < /etc/wireguard/wg0.key`, if it does not have it.
- A v0.5 binary cannot read a journal with the new kinds; the release notes say so, as v0.3.0's did.

### Profiles and the wizard

No built-in profile gains these modules: they need values only the user has (peer keys, an auth key), and closing public SSH should never be a default.

The wizard adds one question after the ports, asked only when `firewall.inbound` applies:

```
? Private access for SSH
  > None: SSH stays reachable from the internet, with keys only
    WireGuard on this server
    Tailscale
```

- **WireGuard:** a peer name (default `laptop`) and its public key, checked with the same parser as the profile, asked again on a bad value. The line under the question shows how to make one (`wg genkey | tee laptop.key | wg pubkey`, or "Add tunnel" in the WireGuard app). After the confirm, the wizard prints the client config and "Connect, then run `ssh admin@10.86.12.1 sudo vps-ready` to close public SSH".
- **Tailscale:** "Auth key (hidden; Enter to log in yourself after)". A pasted key is written to `/run/vps-ready/tailscale-auth-key` (tmpfs, 0600), used as `auth_key_file`, and removed after the apply, whether it succeeded or not. It is never in `vps-ready.toml`. Hidden input needs `dialoguer`'s `password` feature, which adds `zeroize`, a small RustCrypto crate, as the one new dependency.
- **The close step** is offered only when the session already comes through a WireGuard interface or `tailscale0`: "? Accept SSH only through wg0? (y/N)", with the console note under it. Default no.
- The saved `vps-ready.toml` holds `net.wireguard` with its peers (public keys only), `net.tailscale` without a key, and `ssh_via` when chosen.

### Changes to earlier docs

- `architecture.md`: `--deadman` takes `off` (narrowed) and no longer `selftest`; the cloud-init section describes the export as built (hashes from `checksums.txt`, `/etc/vps-ready/profile.toml`); the `ssh_via` confirm rule; the new resources and reloads; M6 items that move to M7.
- `security-baseline.md`: the `net.tailscale` row and step 7 of the order become "a VPN (WireGuard or Tailscale), then `ssh_via`"; `net.wireguard` added; the table's "Tailscale + close 22" row becomes "private SSH (`ssh_via`)".
- `decisions.md`: open question 4 answered (both, with any interface for the close step); a new decision for "public SSH closes only from a session that already comes through the private interface".
- `m3-plan.md`, `m5-plan.md`: their pointers to v0.6.0 point here.
- `testing.md`: the new VM cycle and the manual Tailscale check.
- `release.md`: the manual Tailscale check in the release steps.

### Not in M6

| Idea | M6 | When |
|---|---|---|
| Routing VPN, exit node, subnet routes, peer-to-peer traffic | Host access only | If asked for; needs forward rules next to Docker's |
| IPv6 inside the WireGuard tunnel | IPv4 inside; either family outside | If asked for |
| Preshared keys | Public keys only | If asked for |
| Client keys generated on the server, QR codes | Peers bring their public keys | If phone setup proves too hard; would add `qrcode` |
| More than one WireGuard interface, a configurable name | `wg0` | If asked for |
| Driving Tailscale's browser login | Auth key file, or `tailscale up` by hand | If the engine ever streams command output |
| Tailscale SSH | Never used | Not planned (see above) |
| `ListenAddress` on the tunnel address | Firewall only | Not planned |
| NetBird, ZeroTier modules | `ssh_via` works with their interfaces | If asked for |
| `--deadman=selftest` | Cut | Not planned |
| `net.tunnel` (Cloudflare Tunnel, Tailscale Funnel) | Evaluated, deferred | Next release, with a `behind_tunnel` mode for `deploy.proxy` |
| A built-in `private` profile | The wizard writes it | If the wizard path proves not enough |
| Keeping a public SSH source allowlist with `ssh_via` | Private interface only | If asked for |
| Headscale in CI | Manual Tailscale check | If the manual check proves hard to repeat |

## Testing

**Layer 1:**
- `net.wireguard`: the rendered `wg0.conf` per fixture (`insta`); no `PrivateKey` anywhere in plan output, journal records or `files/<n>` copies (a test greps every byte the engine wrote for the generated key); the derived subnet is stable for a machine ID and differs between two; collisions with an existing route or address refused; peer checks (bad base64, wrong length, duplicate key or name, address outside the subnet or `.1`); removing the session's peer refused; an address change on an active `wg0` from a `wg0` session refused; a hand-made `wg0.conf` not applicable; a missing kernel module not applicable; apply → plan empty; apply → rollback leaves only the key, and the next apply reuses it.
- `net.tailscale`: the apt source for the four codenames; the embedded key's fingerprint; `TailscaleUp` argv has `--auth-key=file:` and never a key; a key file with group or other permissions, or a symlink, refused; `Running` plans no join; no key and not logged in plans the install and the note; rollback runs `tailscale down` only when it was not running.
- `ssh_via`: the ruleset (`insta`) with `iifname`; SSH ports in `allow` left out with the note; refusals 1 to 7, each from a fixture; for random port sets and interfaces (proptest), the session's port is accepted on the session's interface; `verify` fails on a table that still accepts SSH on another interface.
- Confirm: `NotVia` for a new login to the public address; accepted through the interface; a journal without `ssh_via` behaves as before.
- `--deadman=off` refused in an SSH session and with `ssh_via`, accepted with no session; `history` shows it.
- `export cloud-init`: the output per fixture profile (`insta`); hashes taken from a `checksums.txt` fixture for both architectures; refused without `authorized_keys`, with `ssh_via`, with `auth_key_file`, or with a `checksums.txt` that lacks a tarball; the printed script passes `sh -n`, and the YAML parses (in a test only, so no YAML crate in the binary).
- `SSH-009`, `NET-007` and `FW-003` on fixtures (`FW-003`: a database on `0.0.0.0` fails, 80/443 pass, a port reachable only on `wg0` does not count, `docker-proxy` is left to `FW-002`); `SSH-009` skipped without a VPN interface.
- The wizard: each new branch as a transcript snapshot, and the saved profile planning the same as the wizard's.

**Layer 2 (containers):** `net.tailscale` install from Tailscale's real repository on all four images (`tailscale version` runs, `tailscaled` starts, `BackendState` is `NeedsLogin`, rollback removes the source and key). `wireguard-tools` installs; `net.wireguard` is not applicable (no kernel module in the container), which is itself checked.

**Layer 3 (VMs), first boot:** a new cycle, `cloud-init`, on all four images. The harness already boots each image with a NoCloud seed. This cycle builds a profile whose admin key is the job's key, runs `export cloud-init --base-url http://10.0.2.2:<port>` with a `checksums.txt` made from the tarball built in the job, serves that tarball from the runner, and combines the export with the harness's own cloud-config as multipart user-data (cloud-init merges the parts). It boots a fresh overlay and, over SSH as the admin, checks:
- `cloud-init status --wait` ends `done`; `vps-ready history` shows one transaction applied without the timer;
- `SSH-001` to `SSH-007` and `FW-001` pass, a root login is refused, and `plan --profile /etc/vps-ready/profile.toml` plans nothing;
- a second fresh boot with a tampered tarball: `sha256sum -c` fails, nothing is applied, and `cloud-init status` is `error`.

**Layer 3 (VMs), private access:** a new cycle, `private-access`, on all four images, with `--deadman 1m`. The runner is the WireGuard peer: it has passwordless sudo and a kernel with WireGuard, and QEMU forwards a UDP port to the VM's listen port. The peer survives a VM reboot, which a network namespace inside the VM would not. (Locally on Lima, a network namespace in the VM stands in for the runner, without the reboot step.)
1. Apply `net.wireguard` with the runner's public key (and `firewall.inbound`) from public SSH; confirm from a new public login. The runner brings up its side; `ssh admin@<tunnel address>` works.
2. From a session through `wg0`, apply `ssh_via = "wg0"`. During the window: a new login on the forwarded public port times out, the driving public session stays up (`established`), and a confirm from a new `wg0` login succeeds; a new login to the VM's public address from inside the VM (the firewall's other path) is refused by `confirm` with `NotVia`. `SSH-009` passes, `NET-007` passes.
3. Same, not confirmed: at the deadline public SSH works again.
4. After a confirmed `ssh_via`, reboot: public SSH stays closed; SSH through `wg0` works once `wg-quick@wg0` is up; `systemd-analyze verify` finds no ordering cycle.
5. `ssh_via` from the public session is refused (refusal 3), with the printed command.
6. `rollback --last` twice: public SSH reopens, `wg0` goes away, the key stays, and a new apply brings back the same public key.
7. Tailscale: install only (as in layer 2), plus refusal 4 with `tailscaled` disabled.

**Release gate (manual):** Tailscale cannot join in CI without a tailnet. Before tagging v0.6.0, the maintainer runs `net.tailscale` with a tagged one-off key, then `ssh_via = "tailscale0"`, on one Debian 13 and one Ubuntu 24.04 VM, including a reboot, and records the result in the release PR. `release.md` gets the checklist.

## PR sequence

1. **`docs: plan M6`** (this document).
2. **`feat(facts): interfaces, routes, WireGuard and Tailscale state`**: the facts above, `detect` output. *Parallel with 3 and 8.*
3. **`feat(resource): WireguardKey, TailscaleUp and the Tailscale apt source`** (needs M5's #89): the two kinds, their backups and restores, the redacted runner call, stdin for `Cmd`, the embedded key and its weekly check. *Parallel.*
4. **`feat(modules): net.wireguard`** (needs 2, 3): the module, the two reloads, the firewall's UDP rule, `wireguard-config`, `NET-007`.
5. **`feat(modules): net.tailscale`** (needs 2, 3): the module, layer 2 cycle.
6. **`feat(firewall): ssh_via and the confirm through it`** (needs 2): the param, the ruleset change, the refusals and notes, `ssh_via` in `pending-confirm`, `Refusal::NotVia`, `SSH-009`. Testable on its own with a hand-made `wg0` in the VM.
7. **`feat(cli): private access in the wizard`** (needs 4 to 6): the question, the hidden key prompt (`dialoguer`'s `password` feature), the close-step question.
8. **`feat(cli): apply --deadman=off and export cloud-init`**, with the VM `cloud-init` cycle: independent of the VPN work, and first in line. *Parallel.*
9. **`test(vm): private access cycle`** (needs 4 and 6; 5 for step 7), with `FW-003`, since this cycle produces the zero-public-ports host it should show.
10. **`docs(site): private access`** (needs 4 to 7): a guide for both VPNs and the close step, the recovery page, the `modules` reference, the doc changes listed above.
11. **`chore: release v0.6.0`**: the manual Tailscale check, version bump, release notes.

Waves: {8, 2, 3} → {4, 5, 6} → {7, 9} → 10 → 11. If the VPN work needs more VM time, PR 8 can ship alone as v0.6.0 and the rest as v0.6.1.

## Fact check

Checked against upstream docs while writing this plan; items marked VM are checked in PR 4, 6 or 9.

| Claim | Source |
|---|---|
| Kernels: Debian 12 6.1, Debian 13 6.12, Ubuntu 22.04 5.15 (HWE 6.8), Ubuntu 24.04 6.8; WireGuard in mainline since 5.6 | Debian release notes and package index; Ubuntu kernel lifecycle page; wireguard.com install page ("kernels < 5.6" need the module package) |
| `wg-quick`: MTU from the endpoint or default route when unset; `PostUp` with `%i`; `SaveConfig` overwrites at shutdown; `strip`; `wg syncconf wg0 <(wg-quick strip wg0)` reloads "without disrupting active sessions" | `wg-quick(8)` |
| `private-key` must be a file; `syncconf` only changes what differs; `PersistentKeepalive` off by default, "most users will not need this" | `wg(8)` |
| `wg-quick@.service`: oneshot, `ExecReload` with `syncconf`, after `network-online.target`, wanted by `multi-user.target` | wireguard-tools `src/systemd/wg-quick@.service` |
| `syncconf` with a file without `PrivateKey` keeps the loaded key; `wg-quick up` with the key set in `PostUp` | VM |
| `iif` is an index and unsuited to interfaces that come and go; `iifname` matches the name | nftables wiki, "Matching packet metainformation"; loading before `wg0` exists: VM |
| Tailscale repo URLs and suites for bookworm, trixie, jammy, noble; one key for all four (identical files) | pkgs.tailscale.com/stable, downloaded and compared |
| `--auth-key` "if it begins with `file:`, then it's a path to a file"; `--accept-dns` defaults to on; `--ssh` defaults to off; `--login-server`; `--timeout` defaults to blocking | Tailscale docs, `tailscale up` |
| Node key expiry 180 days by default; expiry stops connections; tagged devices have it off by default; disable for trusted servers | Tailscale docs, key expiry |
| One-off, reusable, ephemeral, pre-approved and tagged auth keys; ephemeral nodes removed when idle; auth key expiry does not affect a joined node | Tailscale docs, auth keys |
| No inbound ports needed in most cases | Tailscale docs, firewall ports |
| `BackendState`, `Self.TailscaleIPs`, `Self.KeyExpiry` in `tailscale status --json` | Fixtures captured in PR 2 |
| cloudflared `--token-file` / `TUNNEL_TOKEN_FILE` need 2025.4.0; Cloudflare's service examples put the token in `ExecStart` | Cloudflare docs, tunnel run parameters |
| Funnel: ports 443, 8443, 10000; `ts.net` names only; TLS ends on the device; bandwidth limits; needs the `funnel` attribute, MagicDNS and HTTPS | Tailscale docs, Funnel |
| `runcmd` runs after the network and sshd are up; multipart user-data parts merge | VM (the `cloud-init` cycle) |

## Decisions for the owner

1. **Both VPN modules in v0.6.0, WireGuard first.** Recommended: WireGuard is fully testable in CI and has no third-party control plane; Tailscale is the easier path for many users and its module is small. Alternative: Tailscale only, as the M5 direction had it.
2. **`ssh_via` only from a session that already comes through the interface**, so closing public SSH is always a second apply. Recommended: the private path carries a real login before anything closes. Alternative: allow one apply that brings up the VPN and closes 22, relying on the timer alone.
3. **Firewall only; sshd keeps listening on all addresses.** Recommended: `ListenAddress` on a tunnel address fails at boot when sshd starts first.
4. **The WireGuard subnet is a `/24` in `10.0.0.0/8` derived from the machine ID**, collision-checked, with `address` to override. Recommended: stable without stored state, and different per server, so one laptop can reach several. Alternative: one fixed default subnet (simpler docs, overlapping tunnels across servers).
5. **Rollback keeps the generated WireGuard key.** Recommended: client configs survive a timed-out first setup. Alternative: remove it, for an exact rollback.
6. **Peers bring their public keys; no QR code, no server-generated client keys.** Recommended: the private key never leaves the client, and no `qrcode` dependency. Alternative: `--new-peer` that generates a client key and prints a full config and QR once.
7. **Client config printed after apply and by `vps-ready wireguard-config [PEER]`.** Recommended over printing it only once.
8. **Tailscale auth key only through a root-only file (`file:`) or the wizard's hidden prompt;** no key means the user runs `tailscale up` once; rollback runs `tailscale down`, never `logout`; `--accept-dns=false`; never `--ssh`. Recommended as a set. The hidden prompt adds `zeroize` through `dialoguer`'s `password` feature.
9. **Refuse `ssh_via = "tailscale0"` while the node key expires.** Recommended: otherwise SSH closes on a date months away. Alternative: a note.
10. **A missing console password is a note, not a refusal.** Recommended: rescue mode exists at every major provider, and setting a password is the admin's choice. Alternative: refuse `ssh_via` until a sudo user has a password.
11. **SSH ports in `allow` are left out, with a note, when `ssh_via` is set.** Recommended: profiles that extend `minimal` or `web` keep working. Alternative: refuse until `allow` drops them.
12. **`export cloud-init` is a priority, in the first wave,** with hashes from a user-verified `checksums.txt`, `--deadman=off` at first boot (refused in an SSH session and with `ssh_via`), and a VM cycle that boots the export. Recommended: it is how a server is hardened before it is ever exposed. Alternative: arm the timer at first boot and confirm at the first login (rejected above: a late login finds the hardening rolled back).
13. **Cut `--deadman=selftest`.** Recommended: a loopback probe proves nothing a login would.
14. **Defer `net.tunnel`; when it comes, Cloudflare Tunnel first, with `--token-file`, and `deploy.proxy` behind it on loopback.** Recommended: it changes Caddy's TLS model, needs a provider choice, and loses nothing by waiting (SSH does not depend on it). Alternatives: Cloudflare Tunnel in v0.6.0; Tailscale Funnel only (no custom domains).
15. **No built-in `private` profile;** the wizard writes the zero-public-ports profile. Recommended: a built-in profile cannot name the interface or the peers.
16. **`FW-003` lists every port open to the internet and fails only on ports other than SSH and 80/443.** Recommended: useful on every host without failing every web server. Alternative: fail on any exposed port besides SSH.
17. **CI: the runner is the WireGuard peer; Tailscale is tested for install and refusals only, with a manual join and `ssh_via` check as the release gate.** Recommended over running Headscale in CI, a new third-party image for one job.
18. **Two VPN controls, `SSH-009` (skipped without a VPN interface, no automatic fix) and `NET-007`.** Recommended: no new failures on hosts without a VPN.
