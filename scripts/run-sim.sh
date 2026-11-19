#!/usr/bin/env bash
# Run a read-only routerd demo using the built image's rootfs (chroot + qemu
# binfmt). Only GET APIs are allowed; every mutation returns 403.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IB_IMG="${IB_IMG:-$(ls -t /root/cudy/work/firmware/*sysupgrade*.bin 2>/dev/null | head -1)}"
R="${R:-/root/cudy/work/sim/rootfs}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"
DEMO_USER_PASS_HASH='$6$routerdtr3000$UXRO8PZeZOJaHqQIuxKypH7YtQo/N3KNJswR7b1dbtKo04E0PguFR2guZTfIXcBAwYz6tZhTOit/79A3ZixG50'

[ "$(id -u)" = "0" ] || { echo "run as root"; exit 1; }
[ -x "$ROOT/packaging/files/usr/sbin/routerd" ] || "$ROOT/scripts/build.sh"

# Prepare the rootfs from the image once.
if [ ! -x "$R/usr/sbin/routerd" ]; then
	[ -n "$IB_IMG" ] && [ -f "$IB_IMG" ] || { echo "no image"; exit 1; }
	rm -rf "$R"
	tmp=$(mktemp -d)
	tar -xf "$IB_IMG" -C "$tmp"
	sysdir=$(find "$tmp" -maxdepth 1 -type d -name 'sysupgrade-*' | head -1)
	unsquashfs -q -d "$R" "$sysdir/root" >/dev/null
	rm -rf "$tmp"
fi

# Demo credentials: root/admin (no forced-change prompt in the demo).
sed -i "s|^root:[^:]*:|root:${DEMO_USER_PASS_HASH}:|" "$R/etc/shadow"
chmod 600 "$R/etc/shadow"
mkdir -p "$R/etc/routerd"
rm -f "$R/etc/routerd/must_change"

# Put the simulation-capable binary into the demo rootfs.
install -Dm755 "$ROOT/packaging/files/usr/sbin/routerd" "$R/usr/sbin/routerd"

# Seed a realistic wireless config (the image generates it on first boot).
cat > "$R/etc/config/wireless" <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
	option path 'platform/soc/18000000.wifi'
	option channel '6'
	option band '2g'
	option htmode 'HE40'
	option txpower '20'
	option country 'CN'
	option disabled '0'

config wifi-iface 'default_radio0'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'Cudy-TR3000'
	option encryption 'sae-mixed'
	option key '12345678'
	option hidden '0'
	option disabled '0'

config wifi-device 'radio1'
	option type 'mac80211'
	option path 'platform/soc/18000000.wifi+1'
	option channel '36'
	option band '5g'
	option htmode 'HE80'
	option txpower '23'
	option country 'CN'
	option disabled '0'

config wifi-iface 'default_radio1'
	option device 'radio1'
	option network 'lan'
	option mode 'ap'
	option ssid 'Cudy-TR3000-5G'
	option encryption 'sae'
	option key '12345678'
	option hidden '0'
	option disabled '0'
EOF

# Seed two example port forwards and some DHCP leases for the UI.
if ! grep -q "routerd-demo" "$R/etc/config/firewall" 2>/dev/null; then
	cat >> "$R/etc/config/firewall" <<'EOF'

# routerd-demo
config redirect
	option name 'NAS'
	option target 'DNAT'
	option src 'wan'
	option dest 'lan'
	option proto 'tcp'
	option src_dport '5000'
	option dest_ip '192.168.1.100'
	option dest_port '5000'
	option enabled '1'

config redirect
	option name 'Camera'
	option target 'DNAT'
	option src 'wan'
	option dest 'lan'
	option proto 'tcp udp'
	option src_dport '8554'
	option dest_ip '192.168.1.101'
	option dest_port '8554'
	option enabled '1'
EOF
fi

cat > "$R/tmp/dhcp.leases" <<'EOF'
1893456000 aa:bb:cc:dd:ee:01 192.168.1.101 iPhone-Air *
1893456000 aa:bb:cc:dd:ee:02 192.168.1.102 MacBook-Pro *
1893456000 aa:bb:cc:dd:ee:03 192.168.1.103 NAS *
EOF

sed -i "s/option hostname .*/option hostname 'Cudy-TR3000'/" "$R/etc/config/system" 2>/dev/null || true

mountpoint -q "$R/proc" || mount --bind /proc "$R/proc"
mountpoint -q "$R/sys" || mount --bind /sys "$R/sys"

# Free our ports from a previous demo instance only.
fuser -k "${HTTP_PORT}/tcp" "${HTTPS_PORT}/tcp" 2>/dev/null || true
sleep 1

ROUTERD_HOSTNAME=Cudy-TR3000 ROUTERD_LOG=info \
	nohup chroot "$R" /usr/sbin/routerd \
	--http "0.0.0.0:${HTTP_PORT}" --https "0.0.0.0:${HTTPS_PORT}" --sim \
	> /tmp/routerd-sim.log 2>&1 &
echo $! > /tmp/routerd-sim.pid
sleep 2

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "routerd demo started (pid $(cat /tmp/routerd-sim.pid))"
echo "  local:   https://127.0.0.1"
echo "  lan:     https://${IP:-<host-ip>}"
echo "  login:   root / admin   (read-only, write APIs disabled)"
echo "  log:     /tmp/routerd-sim.log"
echo
curl -sk "https://127.0.0.1:${HTTPS_PORT}/api/health" || true
echo
