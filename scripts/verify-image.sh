#!/usr/bin/env bash
# Verify a built ImmortalWrt 25.12 TR3000 firmware: size budget, rootfs contents,
# apk package database, and removed legacy web/IPv6 stacks.
set -euo pipefail

WORK="${WORK:-/root/cudy/work}"
IMG="${1:-$(ls -t "$WORK"/firmware/*sysupgrade*.bin 2>/dev/null | head -1)}"
[ -n "${IMG:-}" ] && [ -f "$IMG" ] || { echo "no sysupgrade image found"; exit 1; }

SIZE=$(stat -c %s "$IMG")
LIMIT=$((25 * 1024 * 1024))
printf 'image: %s\nsize : %s bytes (%.2f MiB, limit %d MiB)\n' \
	"$IMG" "$SIZE" "$(awk "BEGIN{print $SIZE/1048576}")" $((LIMIT / 1048576))
if [ "$SIZE" -gt "$LIMIT" ]; then
	echo "RESULT: FAIL (over 25 MiB budget)"
	exit 2
fi

rm -rf "$WORK/verify"
mkdir -p "$WORK/verify"
cd "$WORK/verify"
tar -xf "$IMG"
ROOTDIR=$(find . -maxdepth 1 -type d -name 'sysupgrade-*' | head -1)
[ -n "$ROOTDIR" ] || { echo "no sysupgrade-* directory in image"; exit 3; }
cat "$ROOTDIR/CONTROL" 2>/dev/null || true

unsquashfs -q -d rootfs "$ROOTDIR/root" >/dev/null
R="$WORK/verify/rootfs"

fail=0
check() { if eval "$2"; then echo "  OK   $1"; else echo "  FAIL $1"; fail=1; fi; }

echo
echo "== routerd =="
check "binary present + executable" "[ -x '$R/usr/sbin/routerd' ]"
check "binary is dynamic aarch64 (musl)" "file '$R/usr/sbin/routerd' | grep -q 'ARM aarch64.*dynamically linked'"
check "links system OpenSSL 3.5" "readelf -d '$R/usr/sbin/routerd' 2>/dev/null | grep -q 'libssl.so.3' || grep -aq 'libssl.so.3' '$R/usr/sbin/routerd'"
check "init script" "[ -x '$R/etc/init.d/routerd' ]"
check "uci config" "[ -f '$R/etc/config/routerd' ]"
check "first-boot defaults" "[ -x '$R/etc/uci-defaults/99-routerd' ]"
check "embedded UI not on disk" "[ ! -e '$R/www/luci-static' ]"

echo
echo "== stock web / ipv6 / opkg stacks removed =="
check "no uhttpd binary" "[ ! -e '$R/usr/sbin/uhttpd' ]"
check "no uhttpd packages in apk" "! grep -q '^P:uhttpd' '$R/lib/apk/db/installed'"
check "no LuCI packages in apk" "! grep -q '^P:luci' '$R/lib/apk/db/installed'"
check "no LuCI lua tree" "[ ! -d '$R/usr/lib/lua/luci' ]"
check "no LuCI www tree" "[ ! -d '$R/www/luci-static' ]"
check "no odhcp6c binary" "[ ! -e '$R/usr/sbin/odhcp6c' ]"
check "no odhcpd binary" "[ ! -e '$R/usr/sbin/odhcpd' ]"
check "no legacy opkg status" "[ ! -e '$R/usr/lib/opkg/status' ]"
check "apk database present" "[ -f '$R/lib/apk/db/installed' ]"

echo
echo "== required runtime packages (ImmortalWrt 25.12 apk) =="
for p in apk-mbedtls libopenssl3 rpcd rpcd-mod-iwinfo ip-tiny iwinfo wpad-openssl uci ubus netifd dnsmasq-full firewall4 dropbear ppp ppp-mod-pppoe conntrack kmod-nft-tproxy; do
	check "package $p" "grep -q '^P:$p\$' '$R/lib/apk/db/installed'"
done

echo
echo "== sizes =="
du -sh "$R" | sed 's/^/  rootfs: /'
du -h "$R/usr/sbin/routerd" | sed 's/^/  routerd: /'
find "$R" -maxdepth 1 -type d | wc -l | sed 's/^/  top-level dirs: /'

echo
if [ "$fail" -eq 0 ]; then
	echo "RESULT: PASS"
else
	echo "RESULT: FAIL"
	exit 4
fi
