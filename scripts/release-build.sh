#!/bin/sh
# The release build of vps-ready for one target, shared by the release
# workflow and the CI check that rebuilds it and compares hashes.
#
# Usage: scripts/release-build.sh <target>
#
# Needs cargo-auditable, which embeds the dependency list in the binary.
# The toolchain comes from RUSTUP_TOOLCHAIN, which the workflows pin.
set -eu

target=$1
cd "$(dirname "$0")/.."
root=$PWD
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}

# Without these, panic locations embed the checkout, cargo home and rustup
# paths of the build machine, so a rebuild elsewhere differs. Unit separated,
# so paths may contain spaces.
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s\037%s' \
	"--remap-path-prefix=$root=/build" \
	"--remap-path-prefix=$cargo_home=/cargo" \
	"--remap-path-prefix=$rustup_home=/rustup")
export CARGO_ENCODED_RUSTFLAGS

cargo auditable build --release --locked --target "$target"

bin="target/$target/release/vps-ready"
for p in "$root" "$cargo_home" "$rustup_home"; do
	if grep -aqF "$p" "$bin"; then
		echo "error: $bin contains the build path $p" >&2
		exit 1
	fi
done
