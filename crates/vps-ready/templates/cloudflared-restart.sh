# Written by vps-ready (net.tunnel). `vps-ready rollback --last` removes it.
# vps-ready-cloudflared-restart.service runs it when /usr/bin/cloudflared
# changes: it restarts the connector until it runs the new binary.
set -u
bin=/usr/bin/cloudflared
unit=vps-ready-cloudflared.service
retries=0
while :; do
  # dpkg links the old binary to .dpkg-tmp, which can trigger the path unit,
  # before it renames .dpkg-new into place.
  waited=0
  while [ -e "$bin.dpkg-new" ] || [ -e "$bin.dpkg-tmp" ]; do
    [ "$waited" -lt 60 ] || break
    sleep 1
    waited=$((waited + 1))
  done
  # Under Type=notify this returns once the connector is connected.
  systemctl try-restart "$unit" || exit 1
  pid=$(systemctl show --property=MainPID --value "$unit")
  [ "${pid:-0}" != 0 ] || exit 0
  running=$(stat -L -c %d:%i "/proc/$pid/exe" 2>/dev/null) || exit 0
  [ "$running" != "$(stat -L -c %d:%i "$bin")" ] || exit 0
  if [ "$retries" -ge 5 ]; then
    echo "cloudflared runs an old binary" >&2
    exit 1
  fi
  retries=$((retries + 1))
  sleep 5
done
