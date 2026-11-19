#!/usr/bin/env bash
# Build an installable ImmortalWrt sysupgrade image for Cudy TR3000 v1 with
# routerd injected and the stock LuCI/uhttpd web stack removed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IB="${IB:-/root/cudy/dl/ib}"
OUT="${OUT:-/root/cudy/work/firmware}"
PROFILE="${PROFILE:-cudy_tr3000-v1}"
JOBS="${JOBS:-$(nproc)}"

# Remove the stock web UI/server; add a tiny iproute2 for `ip route`.
REMOVE="-luci-light -luci-app-package-manager -luci-compat -luci-lib-base -luci-lib-ipkg -luci-i18n-base-zh-cn -default-settings-chn -uhttpd -uhttpd-mod-ubus -uhttpd-mod-lua"
# ip-tiny: predictable `ip route`; rpcd-mod-iwinfo: ubus iwinfo object.
ADD="ip-tiny rpcd rpcd-mod-iwinfo"

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
