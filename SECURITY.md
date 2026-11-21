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
| `0.8.x` | best effort: fixes ship in the next 0.8.x release |
| `0.7.x` | no: upgrade to 0.8.x |
| `0.6.x` | no: upgrade to 0.8.x |
| `0.5.x` | no: upgrade to 0.8.x |
| `0.4.x` | no: upgrade to 0.8.x |
| `0.3.x` | no: upgrade to 0.8.x |
| `0.2.x` | no: upgrade to 0.8.x |
| `0.1.x` | no: upgrade to 0.8.x |
| `0.1.0-alpha.x` (pre-release) | no: upgrade to 0.8.x |

The latest minor version receives security fixes.

## Verifying a release

Every release ships `checksums.txt`, which lists the tarballs, the `.deb`
files, `install.sh` and the SBOM (`vps-ready-<version>.cdx.json`). The
release workflow signs it with Sigstore and attests the build provenance of
each of those files. The `.deb` files are not signed on their own:
`checksums.txt` and the attestations cover them.

Check the signature first, then each file against `checksums.txt`. Set `V` to
the version you downloaded, for example `V=0.8.0`:

```sh
# 1. Signature on the checksums: signed by the release workflow for this tag
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/bhimrazy/vps-ready/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. Each downloaded file against the signed checksums
sha256sum --check --ignore-missing checksums.txt

# 3. Build provenance of a tarball, a .deb, install.sh or the SBOM
gh attestation verify vps-ready_${V}_amd64.deb \
  --repo bhimrazy/vps-ready \
  --signer-workflow bhimrazy/vps-ready/.github/workflows/release.yml \
  --source-ref "refs/tags/v$V"

# 4. The SBOM attestation on a tarball or a .deb
gh attestation verify vps-ready_${V}_amd64.deb \
  --repo bhimrazy/vps-ready \
  --signer-workflow bhimrazy/vps-ready/.github/workflows/release.yml \
  --source-ref "refs/tags/v$V" \
  --predicate-type https://cyclonedx.org/bom
```

Without `cosign`, step 3 on each file you downloaded replaces steps 1 and 2.

## Official channels

- GitHub Releases: <https://github.com/bhimrazy/vps-ready/releases>
- crates.io: the `vps-ready` crate; `vpsready`, an alias; and `sshd-config`,
  the library that reads the SSH server configuration (from v0.3.0). All three
  are published from this repository by the same release workflow

Anything else (other download sites, container images, packages under other
names) is unofficial.
