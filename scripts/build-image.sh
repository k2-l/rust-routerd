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

REMOVE="-luci -luci-light -luci-base -luci-app-firewall -luci-app-package-manager -luci-lib-base -luci-lib-apk -luci-lib-uqr -luci-i18n-base-zh-cn -luci-mod-admin-full -luci-mod-network -luci-mod-status -luci-mod-system -luci-proto-ipv6 -luci-proto-ppp -luci-theme-bootstrap -luci-compat -rpcd -rpcd-mod-iwinfo -rpcd-mod-file -rpcd-mod-ucode -rpcd-mod-luci -rpcd-mod-rrdns -default-settings-chn -uhttpd -uhttpd-mod-ubus -uhttpd-mod-lua -odhcp6c -odhcpd-ipv6only -conntrack -ip-tiny -dnsmasq-full -wpad-openssl -autocore -kmod-nf-nathelper -bridger -urngd -urandom-seed -getrandom"
ADD="libopenssl3 kmod-nf-conntrack-netlink kmod-nft-tproxy dnsmasq wpad-basic-openssl"

WGET_SHIM_DIR=""
cleanup_wget_shim() {
	if [ -n "${WGET_SHIM_DIR:-}" ] && [ -d "$WGET_SHIM_DIR" ]; then
		rm -rf "$WGET_SHIM_DIR"
	fi
}
trap cleanup_wget_shim EXIT

# Container images without wget still ship curl; bridge apk fetches cleanly when online.
if ! command -v wget >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
	WGET_SHIM_DIR="$(mktemp -d)"
	cat >"$WGET_SHIM_DIR/wget" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
curl_args=(-fsSL)
url=""
while [ $# -gt 0 ]; do
	case "$1" in
		-qO-)
			shift
			;;
		-qO)
			[ "${2:-}" = "-" ] || curl_args+=(-o "${2:?}")
			shift 2
			;;
		-qO*)
			dest="${1#-qO}"
			[ "$dest" = "-" ] || curl_args+=(-o "$dest")
			shift
			;;
		-O)
			[ "${2:-}" = "-" ] || curl_args+=(-o "${2:?}")
			shift 2
			;;
		-O*)
			dest="${1#-O}"
			[ "$dest" = "-" ] || curl_args+=(-o "$dest")
			shift
			;;
		--output-document=*)
			dest="${1#--output-document=}"
			[ "$dest" = "-" ] || curl_args+=(-o "$dest")
			shift
			;;
		--output-document)
			[ "${2:-}" = "-" ] || curl_args+=(-o "${2:?}")
			shift 2
			;;
		-T)
			tval="${2:?}"
			curl_args+=(--connect-timeout "$tval" --speed-limit 1 --speed-time "$tval")
			shift 2
			;;
		-T*)
			tval="${1#-T}"
			curl_args+=(--connect-timeout "$tval" --speed-limit 1 --speed-time "$tval")
			shift
			;;
		--timeout=*)
			tval="${1#--timeout=}"
			curl_args+=(--connect-timeout "$tval" --speed-limit 1 --speed-time "$tval")
			shift
			;;
		--timeout)
			tval="${2:?}"
			curl_args+=(--connect-timeout "$tval" --speed-limit 1 --speed-time "$tval")
			shift 2
			;;
		--header=*)
			curl_args+=(-H "${1#--header=}")
			shift
			;;
		--header)
			curl_args+=(-H "${2:?}")
			shift 2
			;;
		-U)
			curl_args+=(-A "${2:?}")
			shift 2
			;;
		-U*)
			curl_args+=(-A "${1#-U}")
			shift
			;;
		--user-agent=*)
			curl_args+=(-A "${1#--user-agent=}")
			shift
			;;
		--user-agent)
			curl_args+=(-A "${2:?}")
			shift 2
			;;
		-t|--tries)
			shift 2
			;;
		-t*|--tries=*)
			shift
			;;
		-q|--quiet|--no-check-certificate|-S|--server-response|-nv|--no-verbose|-c|--continue|-N|--timestamping)
			shift
			;;
		-4|-6)
			curl_args+=("$1")
			shift
			;;
		--)
			shift
			[ $# -gt 0 ] && url="$1"
			break
			;;
		-*)
			shift
			;;
		*)
			url="$1"
			shift
			;;
	esac
done
[ -n "$url" ] || { echo "wget-shim: missing URL" >&2; exit 2; }
exec curl "${curl_args[@]}" "$url"
EOF
	chmod 0755 "$WGET_SHIM_DIR/wget"
	export PATH="$WGET_SHIM_DIR:$PATH"
fi

mkdir -p "$OUT"
rm -f "$OUT"/*-routerd-*
cd "$IB"
make image \
  PROFILE="$PROFILE" \
  PACKAGES="$REMOVE $ADD" \
  FILES="$ROOT/packaging/files" \
  EXTRA_IMAGE_NAME="mantaos" \
  BIN_DIR="$OUT" \
  -j"$JOBS"

echo
echo "=== images ==="
ls -lh "$OUT"
