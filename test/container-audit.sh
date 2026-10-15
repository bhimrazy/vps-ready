#!/bin/sh
# Run the real binary inside a systemd test container and assert on its output.
#
# Usage: test/container-audit.sh <distro> [binary]      e.g. ubuntu-24.04
#   The binary defaults to $VPS_READY_BIN, then target/release/vps-ready. It must
#   be a Linux binary that matches the container's CPU (the static musl build
#   runs on every distro).
# Needs: docker, jq, and the test image for <distro>:
#   docker build -f test/images/Containerfile --build-arg BASE=ubuntu:24.04 -t vps-ready-test:ubuntu-24.04 test/images
#
# Checks (no total control count, so new controls do not break it):
#   - detect exits 0; audit exits 0 or 1, never 2
#   - every SSH-* finding is pass or fail, never unknown (sshd -T worked)
#   - every KRN-* and NET-* finding is skip (kernel settings belong to the host)
#   - the facts report a detected container
# The container is capped at 512 MB and 1 CPU and is removed afterwards.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-audit-$distro-$$"
tmp=$(mktemp -d)

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

# Log in over SSH once, as on a VPS. On Ubuntu this is what starts sshd
# (socket activation); before that, `sshd -T` and the listener checks see a
# host that no real user would audit.
docker exec "$name" sh -c '
  useradd -m -s /bin/bash -G sudo admin
  install -d -m 700 /root/.ssh
  ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519
  install -d -m 700 -o admin -g admin /home/admin/.ssh
  install -m 600 -o admin -g admin /root/.ssh/id_ed25519.pub /home/admin/.ssh/authorized_keys
'
docker exec "$name" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -i /root/.ssh/id_ed25519 admin@127.0.0.1 true

# run <label> <args...>: run vps-ready as root in the container, keep stdout in
# $tmp/<label>.out and the exit code in $rc. A nonzero exit is not fatal here.
run() {
  label=$1; shift
  rc=0
  docker exec "$name" vps-ready "$@" >"$tmp/$label.out" || rc=$?
}

# Human output first so a CI log is readable on its own.
echo "== $distro: vps-ready detect"
run detect detect; cat "$tmp/detect.out"; detect_rc=$rc
echo "== $distro: vps-ready audit"
run audit audit; cat "$tmp/audit.out"; audit_rc=$rc
run detect-json detect --json; detect_json_rc=$rc
run audit-json audit --json; audit_json_rc=$rc

fail=0
check() { echo "FAIL [$distro]: $*" >&2; fail=1; }

[ "$detect_rc" -eq 0 ] || check "detect exited $detect_rc, expected 0"
[ "$detect_json_rc" -eq 0 ] || check "detect --json exited $detect_json_rc, expected 0"
[ "$audit_rc" -le 1 ] || check "audit exited $audit_rc, expected 0 or 1"
[ "$audit_json_rc" -le 1 ] || check "audit --json exited $audit_json_rc, expected 0 or 1"

jq -e . "$tmp/audit-json.out" >/dev/null 2>&1 || { check "audit --json is not valid JSON"; exit 1; }
jq -e . "$tmp/detect-json.out" >/dev/null 2>&1 || { check "detect --json is not valid JSON"; exit 1; }

# Offenders are listed as "id status", one per line.
bad=$(jq -r '.findings[] | select(.id | startswith("SSH-"))
  | select(.status != "pass" and .status != "fail") | "\(.id) \(.status)"' "$tmp/audit-json.out")
[ -z "$bad" ] || check "SSH controls must be pass or fail after a login (did sshd -T fail?):
$bad"

bad=$(jq -r '.findings[] | select(.id | test("^(KRN|NET)-"))
  | select(.status != "skip") | "\(.id) \(.status)"' "$tmp/audit-json.out")
[ -z "$bad" ] || check "KRN and NET controls must be skipped in a container:
$bad"

# Guard against a vacuous pass: the controls must actually be in the report.
for prefix in SSH KRN NET; do
  n=$(jq --arg p "$prefix-" '[.findings[] | select(.id | startswith($p))] | length' "$tmp/audit-json.out")
  [ "$n" -gt 0 ] || check "no $prefix-* findings in the report"
done

# Serializes as "none", "unknown", or the runtime name (for example "docker").
container=$(jq -r '.virtualization.container' "$tmp/detect-json.out")
case $container in
  null|none|unknown|"") check "container not detected (.virtualization.container = '$container')" ;;
esac

echo "== $distro: $(jq -c .summary "$tmp/audit-json.out"), container=$container"
[ "$fail" -eq 0 ] && echo "OK [$distro]"
exit "$fail"
