# Security policy

`vps-ready` runs as root and changes SSH and firewall configuration, so we treat
its bugs with more care than usual.

## Reporting a vulnerability

Please report privately through GitHub:
**<https://github.com/bhimrazy/vps-ready/security/advisories/new>**

Do not open a public issue for security problems. You should get an
acknowledgement within 72 hours and a fix or mitigation plan within 14 days.
We will credit you in the advisory unless you prefer otherwise.

## Scope

In scope:

- **Lockout bugs are security bugs.** Any way `vps-ready` can leave a server
  unreachable (SSH or firewall change applied without a working path back,
  dead-man switch failing to revert, `confirm` accepted from the old session)
  should be reported here, not as a normal issue.
- Privilege or integrity problems: unsafe file writes, symlink or TOCTOU
  races, command injection, weakened settings reported as hardened.
- Rollback or snapshot failures that lose the previous configuration.
- The release pipeline: checksums, signatures, attestations, `install.sh`.

Out of scope: weaknesses in the distributions themselves, and findings that
require an attacker who is already root.

## Supported versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` | best effort: fixes ship in the next 0.1.x release |
| `0.1.0-alpha.x` (pre-release) | no: upgrade to 0.1.x |

Once v0.1.0 is released, the latest minor version receives security fixes.

## Verifying a release

Every release ships `checksums.txt`, a Sigstore bundle for it, and a GitHub
build-provenance attestation for each tarball and for `install.sh`.

```sh
# 1. Checksums
sha256sum --check --ignore-missing checksums.txt

# 2. Signature on the checksums (keyless, signed by the release workflow)
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/bhimrazy/vps-ready/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 3. Build provenance for a tarball
gh attestation verify vps-ready-<version>-<target>.tar.gz --repo bhimrazy/vps-ready
```

## Official channels

- GitHub Releases: <https://github.com/bhimrazy/vps-ready/releases>
- crates.io: the `vps-ready` crate, and `vpsready`, an alias published from
  this repository by the same release workflow
- Later: apt, rpm and apk repositories announced in the README

Anything else (other download sites, container images, packages under other
names) is unofficial.
