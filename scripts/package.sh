#!/usr/bin/env bash
# Packages a release build under dist/: the tarball and the .deb, with the
# man pages, completions and changelog. Shared by the release workflow and
# the CI job that runs it without publishing.
#
# Usage: scripts/package.sh <target> <deb_arch>
#
# Needs VERSION, SOURCE_DATE_EPOCH and GITHUB_REPOSITORY, the binary from
# scripts/release-build.sh <target>, and Linux x86_64 with dpkg-deb.
set -euo pipefail

target=$1
deb_arch=$2
: "${VERSION:?}" "${SOURCE_DATE_EPOCH:?}" "${GITHUB_REPOSITORY:?}"
cd "$(dirname "$0")/.."

# Pinned nFPM and the SHA-256 of its Linux x86_64 tarball, so a tarball
# replaced upstream, with its checksums.txt, fails the build.
nfpm_version=2.48.0
nfpm_sha256=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750

bin="target/$target/release/vps-ready"
gen=target/gen-docs
# nFPM writes a pre-release such as 0.8.0-rc.1 as 0.8.0~rc.1.
deb_version=${VERSION/-/\~}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Generated from the clap definitions, so they match this build's CLI.
cargo run --locked --package xtask -- gen-docs "$gen"
for f in "$gen"/man/*.1; do gzip -9n <"$f" >"$f.gz"; done

maintainer=$(sed -n 's/^maintainer: //p' packaging/nfpm.yaml)
date=$(date -u -R -d "@$SOURCE_DATE_EPOCH")
printf '%s\n' \
	"vps-ready ($deb_version) unstable; urgency=medium" "" \
	"  * Release notes: https://github.com/$GITHUB_REPOSITORY/releases/tag/v$VERSION" "" \
	" -- $maintainer  $date" | gzip -9n >"$gen/changelog.gz"

# Tarball: deterministic order, owners and mtimes.
name="vps-ready-$VERSION-$target"
rm -rf "dist/$name"
mkdir -p "dist/$name"
cp "$bin" LICENSE-APACHE LICENSE-MIT NOTICE README.md "dist/$name/"
cp -R "$gen/man" "$gen/completions" "dist/$name/"
rm "dist/$name"/man/*.gz
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
	-C dist -cf - "$name" | gzip -n >"dist/$name.tar.gz"

nfpm_file="nfpm_${nfpm_version}_Linux_x86_64.tar.gz"
curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$nfpm_file" \
	"https://github.com/goreleaser/nfpm/releases/download/v$nfpm_version/$nfpm_file"
echo "$nfpm_sha256  $tmp/$nfpm_file" | sha256sum -c -
tar -xzf "$tmp/$nfpm_file" -C "$tmp" nfpm

deb="dist/vps-ready_${VERSION}_${deb_arch}.deb"
ARCH=$deb_arch BINARY=$bin VERSION=$VERSION \
	"$tmp/nfpm" package -f packaging/nfpm.yaml -p deb -t "$deb"
dpkg-deb --info "$deb"
contents=$(dpkg-deb --contents "$deb")
printf '%s\n' "$contents"

fail() {
	echo "error: $deb: $*" >&2
	exit 1
}
[ "$(dpkg-deb --field "$deb" Architecture)" = "$deb_arch" ] || fail "wrong Architecture"
[ "$(dpkg-deb --field "$deb" Version)" = "$deb_version" ] || fail "Version is not $deb_version"
for p in \
	usr/bin/vps-ready \
	usr/share/man/man1/vps-ready.1.gz \
	usr/share/bash-completion/completions/vps-ready \
	usr/share/zsh/vendor-completions/_vps-ready \
	usr/share/fish/vendor_completions.d/vps-ready.fish \
	usr/share/doc/vps-ready/copyright \
	usr/share/doc/vps-ready/changelog.gz; do
	grep -q " ./$p\$" <<<"$contents" || fail "lacks /$p"
done
