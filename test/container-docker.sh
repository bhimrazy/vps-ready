#!/bin/sh
# Apply and roll back deploy.docker with the real binary in a systemd test container.
#
# Usage: test/container-docker.sh <distro> [binary]      e.g. ubuntu-24.04
#   Same binary and image requirements as test/container-audit.sh. Needs docker
#   and jq. `apply` installs Docker from download.docker.com and `docker run`
#   pulls busybox from public.ecr.aws, so the container needs network access.
#
# Cycle: apply --yes -> plan has no changes -> Docker runs with live-restore
# and publishes a port without an address on 127.0.0.1 only: it answers there
# and not on the container's own address -> rollback --last
# -> Docker's source, key and daemon.json are gone, its packages stay, and it
# runs again with its defaults.
# Docker's data directories are volumes, since overlayfs does not stack on the
# container's own. The container is capped at 1 GB and 1 CPU and is removed
# afterwards, with its volumes.
set -eu
cd "$(dirname "$0")/.."

distro=${1:?usage: $0 <distro> [binary]}
bin=${2:-${VPS_READY_BIN:-target/release/vps-ready}}
image="vps-ready-test:$distro"
name="vps-ready-docker-$distro-$$"
tmp=$(mktemp -d)

[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
# POSIX sh keeps running after a trapped signal; exit so Ctrl-C stops the run.
trap 'exit 130' INT TERM

docker run -d --name "$name" --privileged --cgroupns=private \
  --memory 1g --cpus 1 --tmpfs /run --tmpfs /run/lock \
  -v /var/lib/docker -v /var/lib/containerd "$image" >/dev/null

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
# The first bytes of an HTTP reply from <address> <port> inside the container,
# which has no wget or curl; fails within 3 s when nothing answers.
http() {
  ct timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2" && printf "GET / HTTP/1.0\r\n\r\n" >&3 && head -c 8 <&3' _ "$1" "$2"
}
# busybox 1.37 by digest, from a mirror without Docker Hub's pull limits.
busybox=public.ecr.aws/docker/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
managed="/etc/apt/sources.list.d/docker.sources /etc/apt/keyrings/docker.asc /etc/docker/daemon.json"

for f in $managed; do ct test ! -e "$f" || die "$f exists before apply"; done

echo "== $distro: vps-ready apply --yes --module deploy.docker"
rc=0; vr apply --yes --module deploy.docker || rc=$?
[ "$rc" -eq 0 ] || die "apply exited $rc, expected 0"

echo "== $distro: vps-ready plan --json --module deploy.docker"
rc=0; vr plan --json --module deploy.docker >"$tmp/plan.json" || rc=$?
[ "$rc" -eq 0 ] || die "plan exited $rc, expected 0"
jq -e '[.modules[].changes | length] | add == 0' "$tmp/plan.json" >/dev/null ||
  die "plan still has changes after apply"

echo "== $distro: Docker after apply"
ct docker version --format 'docker {{.Server.Version}}'
[ "$(ct docker info --format '{{.LiveRestoreEnabled}}')" = true ] ||
  die "live-restore is not on"
ct docker run -d --name web -p 8080:80 "$busybox" httpd -f -p 80 >/dev/null ||
  die "docker run failed"
ports=$(ct docker port web 80/tcp)
echo "$ports"
[ "$ports" = "127.0.0.1:8080" ] || die "the port is published on $ports, expected 127.0.0.1:8080 only"
# Without docker-proxy (userland-proxy false), the host reaches the port on
# loopback through Docker's NAT rules.
reply=$(http 127.0.0.1 8080) || die "nothing answers on 127.0.0.1:8080"
case $reply in HTTP/1.*) echo "127.0.0.1:8080: $reply" ;; *) die "127.0.0.1:8080 replied $reply" ;; esac
own=$(ct ip -4 -o addr show dev eth0 | awk '{ split($4, a, "/"); print a[1]; exit }')
[ -n "$own" ] || die "the container has no IPv4 address on eth0"
if http "$own" 8080 >/dev/null 2>&1; then die "the port answers on $own:8080"; fi
echo "$own:8080: no answer"
ct docker rm -f web >/dev/null

echo "== $distro: vps-ready rollback --last"
rc=0; vr rollback --last || rc=$?
[ "$rc" -eq 0 ] || die "rollback exited $rc, expected 0"
for f in $managed; do ct test ! -e "$f" || die "$f is left after rollback"; done
ct dpkg-query -W -f '${Status}\n' docker-ce | grep -q 'install ok installed' ||
  die "docker-ce should stay installed"
[ "$(ct docker info --format '{{.LiveRestoreEnabled}}')" = false ] ||
  die "Docker did not restart with its defaults"

# docker-ce is still installed, so the next plan adds its repository back.
echo "== $distro: vps-ready plan --json --module deploy.docker"
vr plan --json --module deploy.docker >"$tmp/plan.json"
jq -e '[.modules[].changes[].id] | index("file:/etc/apt/sources.list.d/docker.sources")' \
  "$tmp/plan.json" >/dev/null || die "the plan does not add Docker's repository back"

echo "OK [$distro]"
