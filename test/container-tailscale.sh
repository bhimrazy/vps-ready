#!/bin/sh
# Apply and roll back net.tailscale with the real binary in a systemd test container.
#
# Usage: test/container-tailscale.sh <distro> [binary]  e.g. debian-13
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq. `apply` installs Tailscale from pkgs.tailscale.com, so the
#   container needs network access.
#
# Cycle: apply --yes with updates.auto and net.tailscale (no auth key, so no
# login) -> plan has no changes -> `tailscale version` runs, tailscaled is
# active and NeedsLogin -> unattended-upgrade --dry-run lists the Tailscale
# origin -> rollback --last -> Tailscale's source, key and origin file are
# gone, the package stays. The container is capped at 1 GB and 1 CPU and is
# removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-tailscale-$distro-$$"
tmp=$(mktemp -d)

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so Ctrl-C stops the run.
trap 'exit 130' INT TERM

# tailscaled needs /dev/net/tun; --privileged gives it.
docker run -d --name "$name" --privileged --cgroupns=private \
  --memory 1g --cpus 1 --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

# Wait for systemd to finish booting ("degraded" is normal in a container).
i=0
until state=$(docker exec "$name" systemctl is-system-running 2>/dev/null); \
      [ "$state" = running ] || [ "$state" = degraded ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "boot timeout ($state)" >&2; exit 1; }
  sleep 1
done

docker cp "$bin" "$name:/usr/local/bin/vps-ready"
docker exec "$name" chmod 755 /usr/local/bin/vps-ready
# Docker's base images keep a package from starting its service; a VPS does not.
docker exec "$name" rm -f /usr/sbin/policy-rc.d

vr() { docker exec "$name" vps-ready "$@"; }
ct() { docker exec "$name" "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }
managed="/etc/apt/sources.list.d/tailscale.sources /etc/apt/keyrings/tailscale.asc
  /etc/apt/apt.conf.d/52vps-ready-tailscale"

for f in $managed; do ct test ! -e "$f" || die "$f exists before apply"; done

cat >"$tmp/tailscale.toml" <<'EOF'
schema = 1

[modules."updates.auto"]

[modules."net.tailscale"]
EOF
docker cp "$tmp/tailscale.toml" "$name:/root/tailscale.toml"

echo "== $distro: vps-ready apply --yes --profile tailscale.toml"
rc=0; vr apply --yes --profile /root/tailscale.toml || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"

echo "== $distro: vps-ready plan --json --profile tailscale.toml"
rc=0; vr plan --json --profile /root/tailscale.toml >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  die "plan still has changes after apply"
jq -e '.modules[] | select(.id == "net.tailscale") | .notes[] |
  select(startswith("no auth_key_file"))' "$tmp/plan.json" >/dev/null ||
  die "plan does not say how to log in"

echo "== $distro: Tailscale after apply"
ct tailscale version
[ "$(ct systemctl is-active tailscaled.service)" = active ] || die "tailscaled is not running"
# tailscaled reports NoState for a moment after it starts.
i=0
until backend=$(ct tailscale status --json --peers=false | jq -r .BackendState); \
      [ "$backend" = NeedsLogin ]; do
  i=$((i + 1)); [ "$i" -lt 30 ] || die "BackendState is $backend, expected NeedsLogin"
  sleep 1
done

echo "== $distro: unattended-upgrade --dry-run"
ct unattended-upgrade --dry-run --debug >"$tmp/uu.log" 2>&1 || {
  cat "$tmp/uu.log"; die "unattended-upgrade --dry-run failed"
}
grep -q 'origin=Tailscale,codename=' "$tmp/uu.log" || {
  cat "$tmp/uu.log"; die "unattended-upgrade does not list the Tailscale origin"
}

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
for f in $managed; do ct test ! -e "$f" || die "$f is left after rollback"; done
# shellcheck disable=SC2016 # dpkg-query's format, not the shell's
ct dpkg-query -W -f '${Status}\n' tailscale | grep -q 'install ok installed' ||
  die "tailscale should stay installed"

echo "OK [$distro]"
