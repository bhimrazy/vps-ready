#!/bin/sh
# Apply and roll back updates.auto with the real binary in a systemd test container.
#
# Usage: test/container-apply.sh <distro> [binary]      e.g. ubuntu-24.04
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq. `apply` runs apt-get, so the container needs network access.
#
# Cycle: apply --yes -> plan has no changes -> UPD-001 passes -> history shows
# "applied" -> rollback --last -> the managed files match their state before.
# unattended-upgrades stays installed by design, so this does not diff all of /etc.
# First, every firewall.inbound ruleset snapshot must pass `nft -c`.
# The container is capped at 512 MB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-apply-$distro-$$"
tmp=$(mktemp -d)
conf=/etc/apt/apt.conf.d

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so Ctrl-C stops the run.
trap 'exit 130' INT TERM

docker run -d --name "$name" --privileged --cgroupns=private \
  --memory 512m --cpus 1 --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

# Wait for systemd to finish booting ("degraded" is normal in a container).
i=0
until state=$(docker exec "$name" systemctl is-system-running 2>/dev/null); \
      [ "$state" = running ] || [ "$state" = degraded ]; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "boot timeout ($state)" >&2; exit 1; }
  sleep 1
done

docker cp "$bin" "$name:/usr/local/bin/vps-ready"
docker exec "$name" chmod 755 /usr/local/bin/vps-ready

vr() { docker exec "$name" vps-ready "$@"; }
die() { echo "FAIL [$distro]: $*" >&2; exit 1; }

# The firewall.inbound rulesets of the unit test snapshots must pass this
# distro's `nft -c`; the snapshot's body follows its second `---` line.
echo "== $distro: nft -c of the rendered rulesets"
for snap in crates/vps-ready/src/modules/firewall_inbound/snapshots/*__ruleset-*.snap; do
  awk 'n >= 2; /^---$/ { n++ }' "$snap" | docker exec -i "$name" nft -c -f - ||
    die "nft -c rejects the ruleset of $snap"
  echo "ok: $(basename "$snap")"
done

# Checksums of the files that exist now; 52vps-ready must not be one of them.
echo "== $distro: before"
docker exec "$name" sh -c "cd $conf && test ! -e 52vps-ready && sha256sum * >/tmp/before.sha"
docker exec "$name" cat /tmp/before.sha

echo "== $distro: vps-ready apply --yes --module updates.auto"
rc=0; vr apply --yes --module updates.auto || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"

echo "== $distro: vps-ready plan --json --module updates.auto"
rc=0; vr plan --json --module updates.auto >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
cat "$tmp/plan.json"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  die "plan still has changes after apply"

echo "== $distro: vps-ready audit --json"
rc=0; vr audit --json >"$tmp/audit.json" || rc=$?
[ "$rc" -le 1 ] || die "audit exited $rc, expected 0 or 1"
jq -r '.findings[] | select(.id == "UPD-001") | "UPD-001 \(.status)"' "$tmp/audit.json"
jq -e '.findings[] | select(.id == "UPD-001" and .status == "pass")' "$tmp/audit.json" >/dev/null ||
  die "UPD-001 is not pass after apply"

echo "== $distro: vps-ready history"
vr history
vr history --json >"$tmp/history.json"
jq -e '.[0] | .state == "applied" and .modules == ["updates.auto"]' "$tmp/history.json" >/dev/null ||
  die "newest transaction is not applied"

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
vr history --json >"$tmp/history.json"
jq -e '.[0].state == "rolled-back"' "$tmp/history.json" >/dev/null ||
  die "newest transaction is not rolled back"

docker exec "$name" sh -c "cd $conf && test ! -e 52vps-ready && sha256sum -c --quiet /tmp/before.sha" ||
  die "managed files differ from the state before apply"
docker exec "$name" dpkg-query -W -f '${Status}\n' unattended-upgrades | grep -q 'install ok installed' ||
  die "unattended-upgrades should stay installed"

echo "OK [$distro]"
