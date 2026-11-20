#!/usr/bin/env bash
# Build an installable ImmortalWrt 25.12 sysupgrade image for Cudy TR3000 v1
# with routerd injected and stock LuCI/uhttpd/IPv6 daemons stripped.
# Requires ImmortalWrt 25.12 ImageBuilder (apk-based); 24.10 is not supported.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IB="${IB:-/root/cudy/dl/ib}"
OUT="${OUT:-/root/cudy/work/firmware}"
PROFILE="${PROFILE:-cudy_tr3000-v1}"
JOBS="${JOBS:-$(nproc)}"

if [ ! -d "$IB" ]; then
	echo "ERROR: ImmortalWrt 25.12 ImageBuilder directory not found: $IB" >&2
	exit 1
fi

if ! grep -Eq '25\.12' "$IB/include/version.mk" "$IB/.config" "$IB/repositories" 2>/dev/null; then
	echo "ERROR: $IB is not ImmortalWrt 25.12 ImageBuilder (24.10 and earlier are no longer supported)." >&2
	exit 1
fi

REMOVE="-luci-light -luci-app-package-manager -luci-compat -luci-lib-base -luci-lib-apk -luci-i18n-base-zh-cn -default-settings-chn -uhttpd -uhttpd-mod-ubus -uhttpd-mod-lua -odhcp6c -odhcpd-ipv6only"
ADD="libopenssl3 ip-tiny rpcd rpcd-mod-iwinfo conntrack"

mkdir -p "$OUT"
cd "$IB"
make image \
  PROFILE="$PROFILE" \
  PACKAGES="$REMOVE $ADD" \
  FILES="$ROOT/packaging/files" \
  EXTRA_IMAGE_NAME="routerd" \
  BIN_DIR="$OUT" \
  -j"$JOBS"

echo
echo "=== images ==="
ls -lh "$OUT"
