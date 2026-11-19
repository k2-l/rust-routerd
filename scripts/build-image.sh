#!/usr/bin/env bash
# Build an installable ImmortalWrt sysupgrade image for Cudy TR3000 v1 with
# routerd injected and stock LuCI/uhttpd/IPv6 daemons stripped.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IB="${IB:-/root/cudy/dl/ib}"
OUT="${OUT:-/root/cudy/work/firmware}"
PROFILE="${PROFILE:-cudy_tr3000-v1}"
JOBS="${JOBS:-$(nproc)}"

REMOVE="-luci-light -luci-app-package-manager -luci-compat -luci-lib-base -luci-lib-ipkg -luci-i18n-base-zh-cn -default-settings-chn -uhttpd -uhttpd-mod-ubus -uhttpd-mod-lua -odhcp6c -odhcpd-ipv6only"
ADD="ip-tiny rpcd rpcd-mod-iwinfo conntrack"

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
