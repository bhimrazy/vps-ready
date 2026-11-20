#!/bin/sh
# net.wireguard in a systemd test container: wireguard-tools installs, and the
# module is not applicable without the kernel's WireGuard module.
#
# Usage: test/container-wireguard.sh <distro> [binary]  e.g. debian-13
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq, and network access for apt.
#
# Cycle: `plan` says net.wireguard does not apply, since the container sees
# no /sys/module/wireguard and cannot load it (on a host that has the module
# loaded the container sees it, and that check is skipped with a note) ->
# apt-get install --no-install-recommends wireguard-tools works -> wg,
# wg-quick and the wg-quick@.service template are there, and the template's
# ExecReload runs `wg syncconf`, which net.wireguard's drop-in blanks. The
# container is capped at 1 GB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-wireguard-$distro-$$"
tmp=$(mktemp -d)

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
trap 'exit 130' INT TERM

docker run -d --name "$name" --privileged --cgroupns=private \
  --memory 1g --cpus 1 --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

i=0
until state=$(docker exec "$name" systemctl is-system-running 2>/dev/null); \
      [ "$state" = running ] || [ "$state" = degraded ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "boot timeout ($state)" >&2; exit 1; }
  sleep 1
done

docker cp "$bin" "$name:/usr/local/bin/vps-ready"
docker exec "$name" chmod 755 /usr/local/bin/vps-ready

vr() { docker exec "$name" vps-ready "$@"; }
ct() { docker exec "$name" "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }

# A peer key made up at run time: 32 bytes of 1, in base64.
peer=$(head -c 32 /dev/zero | tr '\0' '\1' | base64)
printf '%s\n' 'schema = 1' '[modules."net.wireguard"]' \
  "peers = [{ name = \"laptop\", public_key = \"$peer\", host = 2 }]" >"$tmp/wg.toml"
docker cp "$tmp/wg.toml" "$name:/root/wg.toml"

echo "== $distro: vps-ready plan --json --profile wg.toml"
rc=0; vr plan --json --profile /root/wg.toml >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -r '.modules[] | select(.id == "net.wireguard") | "\(.status): \(.reason // "")"' "$tmp/plan.json"
if ct test -e /sys/module/wireguard; then
  echo "note [$distro]: the host has WireGuard loaded, so the container sees it; not-applicable check skipped"
else
  jq -e '.modules[] | select(.id == "net.wireguard") | .status == "not-applicable"
    and (.reason | test("WireGuard"))' "$tmp/plan.json" >/dev/null ||
    die "net.wireguard applies in a container without the kernel module"
fi

echo "== $distro: wireguard-tools"
ct sh -c 'apt-get -o Acquire::Retries=5 update -q >/dev/null &&
  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y -q \
  --no-install-recommends wireguard-tools >/dev/null' || die "wireguard-tools did not install"
ct wg --version
ct sh -c 'command -v wg-quick' >/dev/null || die "wg-quick is missing"
ct systemctl cat wg-quick@wg0.service >"$tmp/unit" || die "the wg-quick@.service template is missing"
grep -q '^ExecReload=.*syncconf' "$tmp/unit" || die "the template's ExecReload does not run syncconf"
[ "$(ct stat -c %a /etc/wireguard)" = 700 ] || die "/etc/wireguard is not 0700"

echo "OK [$distro]"
