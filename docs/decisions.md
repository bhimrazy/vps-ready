# Decisions and open questions

## Decided (recommended; revisit if you disagree)

| # | Decision | Why | Alternative considered |
|---|---|---|---|
| D1 | **Rust (decided 2026-10-11)** | The author wants to master Rust; exhaustive enums + `match` keep the transaction state machine and reversibility labels from being half-handled; no GC, ~3 MB static musl binaries; strong parser/fuzz story for `sshd -T`, os-release and nft output; Ubuntu is moving to Rust (sudo-rs, uutils coreutils). Accepted costs: smaller sysadmin contributor pool, slower compiles, hand-written release pipeline | Go: faster to v0.3, bigger contributor pool. Rejected because the author's goal is Rust mastery and the architecture is identical in both. Bash: only for install.sh |
| D2 | **Modules declare resources; one engine applies and rolls back** | Risk lives in one heavily tested place | Each module has its own apply/rollback (more code, more bugs) |
| D3 | **Controls in TOML with a closed check vocabulary** | Reviewable without reading Rust; maps to CIS/Lynis IDs | Full DSL (scope creep) / checks written in Rust code (less auditable) |
| D4 | **TOML profiles** | No YAML `no`→`false` foot-guns | YAML (more familiar) |
| D5 | **Drop-in files only** (`00-vps-ready.conf`) | Beats cloud-init overrides; easy to remove | Editing main config files |
| D6 | **SSH port stays 22 by default** | Port change = 5 lockout surfaces for log-noise reduction only | Random high port |
| D7 | **Dead-man switch + new-session confirm** for ssh/firewall | The one thing nobody does fully | Trust the open session (wrong) |
| D8 | **Read-only `audit` ships first** (v0.1) | Useful immediately, zero risk, builds trust | Ship apply first |
| D9 | **Ubuntu/Debian → RHEL → Alpine** | Most VPS images are Ubuntu/Debian | All at once |
| D10 | **MIT OR Apache-2.0, DCO, no CLA** | Rust-standard dual license: Apache patent grant, MIT for GPLv2 compatibility, embeddable by providers | Apache-2.0 only, GPL-3.0 |
| D11 | **Signed + reproducible releases, SLSA L3, immutable releases, no self-update** | Root tool → trust is the product | Plain GitHub releases |
| D12 | **Caddy** default reverse proxy | Auto HTTPS, minimal config | Nginx, Traefik |
| D13 | **Rust main; Go companion optional and unscheduled** | One language done well beats two done halfway; the M3 `sshd-config` crate already gives a standalone library to practise publishing | Build the first slice in both languages, then pick (dropped) |
| D14 | **Name `vps-ready` everywhere** (repo, crate, command); `vpsready` is a published alias crate and an install-time command shortcut | One name to remember; owning `vpsready` too (and `vps_ready`, which crates.io treats as the same as `vps-ready`) blocks look-alike crates. Both were free on crates.io as of 2026-10-11 | Different names for repo and command; coined names such as `battenup` (research kept in the planning notes) |
| D15 | **GitHub owner: personal account `bhimrazy`**; repo private until v0.1.0 | Nothing to show until v0.1.0; no org overhead for a solo project | A new org now. Move to one later if co-maintainers join |
| D16 | **Release pipeline hand-written** (not cargo-dist) | With only two musl targets, a generated several-hundred-line workflow isn't justified, and every release step of a root tool should be auditable line by line | cargo-dist: still a valid option to revisit if installers or targets multiply |
| D17 | **Templates: `askama`** | Compile-time checked: a typo in a config template is a build error, not a runtime surprise on a server | Runtime template engines (errors surface only when rendered); `format!` strings (unreadable for whole config files) |
| D18 | **No async runtime** | The tool is sequential: one transaction, a handful of subprocesses. `std::process::Command` with timeouts is enough; no extra runtime in the binary or in the learning curve | tokio (bigger binary, async everywhere for no gain) |

### D13 in short

- Rust is the main and only scheduled language.
- The earlier plan (build the first slice in both Go and Rust, then pick) was dropped: the deciding factor was the learning goal, and building the slice twice would delay v0.1.0.
- A Go companion (for example a small `goss`-style checker) stays optional and has no milestone. Start it only if there's time and interest after v0.1.0.
- The architecture in [the architecture doc](architecture.md) is language-neutral, so nothing in the design depends on this choice.

## Open: you decide

1. **How opinionated is the default?** One recommended profile ("just make it safe") vs always showing the module picker. *Suggestion:* recommended by default, with "Customize" one keypress away.
2. **Brute-force default for the web profile:** fail2ban (simple, local) vs CrowdSec (stronger, phones home). *Suggestion:* fail2ban by default, CrowdSec opt-in.
3. **Should we bundle or call out to ssh-audit/Lynis?** *Suggestion:* port the essential SSH checks natively, and call Lynis only if it's installed.
4. **Is Tailscale a first-class module** (third-party control plane), or do we offer only WireGuard? *Suggestion:* both, with Tailscale as the easy path.
5. **Fork or contribute instead?** If hostveil or koncreet look closer to your goals after the labs, contributing is a legitimate choice. The research says the gap is in *trust and quality*, not features.
