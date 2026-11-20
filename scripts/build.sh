#!/usr/bin/env bash
# Build routerd for ImmortalWrt 25.12 / Cudy TR3000 (aarch64, musl, dynamically
# linked to firmware-provided OpenSSL 3.5 libssl.so.3 / libcrypto.so.3).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IB="${IB:-/root/cudy/dl/ib}"
export PATH="/root/.cargo/bin:$PATH"
export CC_aarch64_unknown_linux_musl=/opt/musl/bin/aarch64-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=/opt/musl/bin/aarch64-linux-musl-ar
export RANLIB_aarch64_unknown_linux_musl=/opt/musl/bin/aarch64-linux-musl-ranlib
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/opt/musl/bin/aarch64-linux-musl-gcc

# Locate ImmortalWrt 25.12 target staging_dir containing OpenSSL 3.5 headers & libs
STAGING_USR="${STAGING_USR:-$(find "$IB/staging_dir" -maxdepth 3 -type d -path '*/target-aarch64_*/usr' 2>/dev/null | head -1)}"
if [ -z "$STAGING_USR" ] || [ ! -f "$STAGING_USR/include/openssl/ssl.h" ]; then
	echo "ERROR: OpenSSL 3.5 headers not found in ImmortalWrt 25.12 staging_dir (IB=$IB)." >&2
	echo "Set STAGING_USR=/path/to/staging_dir/target-aarch64_cortex-a53_musl/usr" >&2
	exit 1
fi

export OPENSSL_NO_VENDOR=1
export OPENSSL_DIR="$STAGING_USR"
export OPENSSL_LIB_DIR="$STAGING_USR/lib"
export OPENSSL_INCLUDE_DIR="$STAGING_USR/include"
# Dynamically link system musl libc + firmware /usr/lib/libssl.so.3 & libcrypto.so.3
export RUSTFLAGS="-C target-feature=-crt-static -C link-arg=-L$STAGING_USR/lib -C link-arg=-Wl,--rpath=/usr/lib -C link-arg=-Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1"

cd "$ROOT"
# rust-embed reads assets at compile time; force the crate to rebuild so UI
# edits are always embedded.
touch src/assets.rs
cargo build --release --target aarch64-unknown-linux-musl

BIN="$ROOT/target/aarch64-unknown-linux-musl/release/routerd"
install -Dm755 "$BIN" "$ROOT/packaging/files/usr/sbin/routerd"
chmod 0755 "$ROOT/packaging/files/etc/init.d/routerd" \
           "$ROOT/packaging/files/etc/uci-defaults/99-routerd"

echo
ls -lh "$ROOT/packaging/files/usr/sbin/routerd"
file "$ROOT/packaging/files/usr/sbin/routerd"
aarch64-linux-musl-readelf -d "$ROOT/packaging/files/usr/sbin/routerd" | grep NEEDED || true
sha256sum "$ROOT/packaging/files/usr/sbin/routerd"
