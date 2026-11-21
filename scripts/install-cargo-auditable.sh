#!/bin/sh
# Installs the pinned cargo-auditable from its crates.io .crate, checked
# against the SHA-256 that the crates.io index records for it, with the
# crate's own Cargo.lock.
set -eu

version=0.7.7
sha256=ccdd489bc94d1338cd04389a842e00661300331ec915fb376b4810ef7d480b5d

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
crate="$dir/cargo-auditable-$version.crate"
curl --proto '=https' --tlsv1.2 -fsSL -o "$crate" \
	"https://static.crates.io/crates/cargo-auditable/cargo-auditable-$version.crate"
echo "$sha256  $crate" | sha256sum -c -
tar -xzf "$crate" -C "$dir"
cargo install --locked --path "$dir/cargo-auditable-$version"
